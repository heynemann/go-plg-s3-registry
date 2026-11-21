package contract

import (
	"context"
	"embed"
	"reflect"

	"github.com/heynemann/go-plg"
	_ "github.com/heynemann/go-plg/guest/lua" // The rewards example runs Lua guests.
)

const Module = "github.com/heynemann/go-plg-s3-registry/examples/rewards/contract"
const Version = "v1.0.0" // The sample packer creates this offline contract version.

//go:embed contract.go
var source embed.FS

// Source returns the contract-only source for the local module fixture.
func Source() ([]byte, error) { return source.ReadFile("contract.go") }

type adapter struct {
	WAccept func(context.Context, string) (bool, error)
}

func (a *adapter) Accept(ctx context.Context, value string) (bool, error) {
	return a.WAccept(ctx, value)
}

func init() {
	plg.MustRegisterContract(plg.Contract{Interface: reflect.TypeFor[Rule](), Adapter: reflect.TypeFor[adapter](), Source: source})
}
