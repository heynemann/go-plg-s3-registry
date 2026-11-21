package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/bytedance/sonic"
	"github.com/heynemann/go-plg-s3-registry/dataplane"
	api "github.com/heynemann/go-plg-s3-registry/examples/rewards/gen"
	_ "modernc.org/sqlite"
)

const awardCents = 100

// A delivery is the operation journal; a row in awards is the actual award.
// Completing a pending delivery and writing its award are one transaction.
const schema = `
CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY NOT NULL,
    subject TEXT NOT NULL,
    region TEXT NOT NULL,
    tier TEXT NOT NULL,
    receipt BLOB NOT NULL,
    plugin_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ineligible', 'delivered'))
);
CREATE TABLE IF NOT EXISTS awards (
    delivery_id TEXT PRIMARY KEY NOT NULL REFERENCES deliveries(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents = 100)
);`

func openDB(ctx context.Context, path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: abs, RawQuery: "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	// SQLite serializes writers. Use one connection here and a busy timeout for
	// other example processes sharing this same file.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

const projection = `deliveries.status, COALESCE(awards.amount_cents, 0), deliveries.plugin_digest`
const byID = ` FROM deliveries LEFT JOIN awards ON awards.delivery_id = deliveries.id WHERE deliveries.id = ?`

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readDelivery(ctx context.Context, db queryRower, id string) (api.Delivery, error) {
	d := api.Delivery{ID: id}
	err := db.QueryRowContext(ctx, `SELECT `+projection+byID, id).
		Scan(&d.Status, &d.AmountCents, &d.PluginDigest)
	return d, err
}

func readReservation(ctx context.Context, db *sql.DB, id string, body api.Reservation) (api.Delivery, bool, error) {
	d := api.Delivery{ID: id}
	var identical bool
	err := db.QueryRowContext(ctx, `SELECT `+projection+`, subject = ? AND region = ? AND tier = ?`+byID,
		body.Subject, body.Region, body.Tier, id).
		Scan(&d.Status, &d.AmountCents, &d.PluginDigest, &identical)
	return d, identical, err
}

func readAttempt(ctx context.Context, db *sql.DB, id string) (api.Delivery, string, []byte, error) {
	d := api.Delivery{ID: id}
	var tier string
	var receipt []byte
	err := db.QueryRowContext(ctx, `SELECT `+projection+`,
		CASE WHEN status = 'pending' THEN tier ELSE '' END,
		CASE WHEN status = 'pending' THEN receipt END`+byID, id).
		Scan(&d.Status, &d.AmountCents, &d.PluginDigest, &tier, &receipt)
	return d, tier, receipt, err
}

func insertDelivery(ctx context.Context, db *sql.DB, id string, body api.Reservation, receipt dataplane.Receipt) (bool, error) {
	data, err := sonic.ConfigStd.Marshal(receipt)
	if err != nil {
		return false, err
	}
	result, err := db.ExecContext(ctx, `INSERT INTO deliveries (id, subject, region, tier, receipt, plugin_digest)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, id, body.Subject, body.Region, body.Tier, data, receipt.Digest)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func completeDelivery(ctx context.Context, db *sql.DB, id string, accepted bool) (api.Delivery, error) {
	status := api.Ineligible
	if accepted {
		status = api.Delivered
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return api.Delivery{}, err
	}
	defer tx.Rollback()

	// The first statement is a write, not a read-to-write upgrade. Competing
	// attempts may evaluate the pure rule, but only one can complete the row.
	result, err := tx.ExecContext(ctx, `UPDATE deliveries SET status = ? WHERE id = ? AND status = 'pending'`, status, id)
	if err != nil {
		return api.Delivery{}, fmt.Errorf("complete delivery: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return api.Delivery{}, err
	}
	if n == 1 && accepted {
		if _, err := tx.ExecContext(ctx, `INSERT INTO awards (delivery_id, amount_cents) VALUES (?, ?)`, id, awardCents); err != nil {
			return api.Delivery{}, fmt.Errorf("record award: %w", err)
		}
	}
	d, err := readDelivery(ctx, tx, id)
	if err != nil {
		return api.Delivery{}, err
	}
	return d, tx.Commit()
}
