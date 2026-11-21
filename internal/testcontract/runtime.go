package testcontract

import (
	"context"
	"embed"
	"reflect"

	"github.com/heynemann/go-plg"
)

//go:embed contract.go
var Source embed.FS

type adapter struct {
	WAccept func(context.Context, string) (bool, error)
}

func (a *adapter) Accept(ctx context.Context, value string) (bool, error) {
	return a.WAccept(ctx, value)
}

func init() {
	plg.MustRegisterContract(plg.Contract{Interface: reflect.TypeFor[Rule](), Adapter: reflect.TypeFor[adapter](), Source: Source})
}
