// Package contract defines the rewards host's eligibility plugin interface.
package contract

import "context"

// Rule decides whether a tier is eligible. It performs no delivery side effects.
type Rule interface {
	Accept(ctx context.Context, value string) (bool, error)
}
