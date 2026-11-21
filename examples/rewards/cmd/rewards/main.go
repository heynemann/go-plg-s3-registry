// The rewards example serves a local-only HTTP adapter to the registry SDK.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/heynemann/go-plg"
	"github.com/heynemann/go-plg-s3-registry/dataplane"
	"github.com/heynemann/go-plg-s3-registry/examples/rewards/contract"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rewards:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("rewards", flag.ContinueOnError)
	deployment := flags.String("config", "", "registry deployment JSON containing public trust")
	endpoint := flags.String("endpoint", "", "loopback Floci HTTP origin")
	path := flags.String("db", "", "SQLite file for the delivery journal and award ledger")
	listen := flags.String("listen", "127.0.0.1:8080", "loopback HTTP listener; port 0 chooses a free port")
	poll := flags.Duration("poll-interval", 250*time.Millisecond, "registry polling interval")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *deployment == "" || *endpoint == "" || *path == "" || *poll <= 0 || flags.NArg() != 0 {
		return errors.New("--config, --endpoint, --db and a positive --poll-interval are required; no positional arguments")
	}
	addr, err := loopbackAddress(*listen, true)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	transport, origin, err := localTransport(*endpoint)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	cfg, err := loadHostConfig(*deployment, transport, origin, *poll)
	if err != nil {
		return fmt.Errorf("load deployment: %w", err)
	}
	db, err := openDB(ctx, *path)
	if err != nil {
		return fmt.Errorf("open delivery database: %w", err)
	}
	defer db.Close()

	host, err := dataplane.Attach[contract.Rule](ctx, nil, cfg, plg.WithLuaPlugins())
	if err != nil {
		return fmt.Errorf("attach rewards rule: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = host.Close(closeCtx)
	}()
	rewards := &rewards{host: host, db: db}
	handler, err := rewards.handler(ctx)
	if err != nil {
		return fmt.Errorf("load HTTP contract: %w", err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	// A fresh destination may have no active decision. Start polling without
	// blocking the listener; readiness reflects the SDK's effective view.
	pollCtx, stopPolling := context.WithCancel(context.Background())
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		_ = host.Run(pollCtx)
	}()
	defer func() {
		stopPolling()
		<-pollDone
	}()

	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	fmt.Printf("listening http://%s\n", listener.Addr())
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
		rewards.draining.Store(true)
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
