package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
)

func invalidInput(reason string) error {
	return fmt.Errorf("%w: %s", registry.ErrInvalid, reason)
}

func readOperationInput(cmd *cobra.Command, path string, dest any, individualFlags ...string) error {
	if !cmd.Flags().Changed("request") {
		return nil
	}
	for _, flag := range individualFlags {
		if cmd.Flags().Changed(flag) {
			return invalidInput("--request cannot be combined with individual request flags")
		}
	}
	return readInput(path, dest)
}

func readInput(path string, dest any) error {
	if path == "" {
		return invalidInput("a required JSON input file was not specified; see --help")
	}
	data, err := boundedFile(path, registry.MaxRecordBytes)
	if err != nil {
		return invalidInput("cannot read a nonempty, bounded JSON input file")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || !utf8.Valid(data) || !uniqueJSON(data, reflect.TypeOf(dest)) {
		return invalidInput("expected one JSON object with known, unique field names")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(dest); err != nil {
		return invalidInput("JSON input has unknown fields or invalid field types")
	}
	return nil
}

// encoding/json matches struct fields case-insensitively and lets the last
// duplicate win. Check exact field names, keeping map keys case-sensitive.
func uniqueJSON(data []byte, shape reflect.Type) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !uniqueValue(decoder, shape, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func uniqueValue(decoder *json.Decoder, shape reflect.Type, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	for shape != nil && shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err = decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return false
			}
			child, known := inputField(shape, key)
			if _, duplicate := seen[key]; duplicate || !known || !uniqueValue(decoder, child, depth+1) {
				return false
			}
			seen[key] = struct{}{}
		}
	case json.Delim('['):
		var child reflect.Type
		if shape != nil && (shape.Kind() == reflect.Array || shape.Kind() == reflect.Slice) {
			child = shape.Elem()
		}
		for decoder.More() {
			if !uniqueValue(decoder, child, depth+1) {
				return false
			}
		}
	default:
		return true
	}
	_, err = decoder.Token()
	return err == nil
}

func inputField(shape reflect.Type, key string) (reflect.Type, bool) {
	if shape == nil {
		return nil, true
	}
	switch shape.Kind() {
	case reflect.Map:
		return shape.Elem(), true
	case reflect.Struct:
		for i := range shape.NumField() {
			field := shape.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" {
				name = field.Name
			}
			if field.IsExported() && name != "-" && key == name {
				return field.Type, true
			}
		}
		return nil, false
	default:
		return nil, true // Decode checks the type of the value separately.
	}
}
