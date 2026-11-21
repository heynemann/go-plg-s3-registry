// Package testcontract defines the host contract used by the registry lifecycle test.
package testcontract

import "context"

type Rule interface {
	Accept(ctx context.Context, value string) (bool, error)
}
