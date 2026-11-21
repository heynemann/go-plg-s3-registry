package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/bytedance/sonic"

	"github.com/heynemann/go-plg-s3-registry/examples/rewards/plugins"
)

func main() {
	out := flag.String("out", "", "output directory for first.plg and second.plg")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	commits, err := plugins.Pack(ctx, "", *out)
	if err == nil {
		err = sonic.ConfigStd.NewEncoder(os.Stdout).Encode(commits)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack rewards plugins: %v\n", err)
		os.Exit(1)
	}
}
