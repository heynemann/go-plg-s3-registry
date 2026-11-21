package target

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const zeroSeed = "0000000000000000000000000000000000000000000000000000000000000000"

func mustCompile(t testing.TB, expression string, attrs map[string]string) *Program {
	t.Helper()
	p, err := Compile(Spec{Version: 1, Expression: expression, Attributes: attrs, Seed: zeroSeed})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return p
}

func TestBucketV1Goldens(t *testing.T) {
	const sequenceSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	for _, tc := range []struct {
		name, environment, plugin, seed, subject string
		word                                     uint64
		bucket                                   uint16
	}{
		// From docs/specs/data-plane.md.
		{"user-1", "prod", "eligibility", zeroSeed, "user-1", 0x65ff176b25993b68, 3984},
		{"user-137", "prod", "eligibility", zeroSeed, "user-137", 0xea125ee09e64c822, 9143},
		{"user-2", "prod", "eligibility", zeroSeed, "user-2", 0x335cdf60c6eb4152, 2006},
		// Nonzero seed, equal concatenations of distinct IDs, and opaque subject bytes.
		{"framing-a-bc", "a", "bc", sequenceSeed, "\x00A\xff", 0x229aff46f83bbc5f, 1351},
		{"framing-ab-c", "ab", "c", sequenceSeed, "\x00A\xff", 0x983ac42060cec0b0, 5946},
		{"subject-case", "a", "bc", sequenceSeed, "\x00a\xff", 0xf296ae9d8bf1fea2, 9476},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Compile(Spec{Version: 1, Seed: tc.seed})
			if err != nil {
				t.Fatal(err)
			}
			subject := []byte(tc.subject)
			if word := bucketWord(tc.environment, tc.plugin, &p.seed, subject); word != tc.word {
				t.Errorf("digest prefix = %016x, want %016x", word, tc.word)
			}
			for _, rung := range []uint16{0, tc.bucket, tc.bucket + 1, 10_000} {
				want := Result{Match: true, Bucket: tc.bucket, Candidate: rung > tc.bucket}
				got, err := p.Evaluate(tc.environment, tc.plugin, subject, nil, rung)
				if err != nil || got != want {
					t.Errorf("Evaluate(rung=%d) = %+v, %v, want %+v", rung, got, err, want)
				}
			}
		})
	}
}

func TestCandidateAssignmentIsMonotonic(t *testing.T) {
	p := mustCompile(t, "eligible", map[string]string{"eligible": "bool"})
	for i := range 256 {
		subject := []byte(fmt.Sprintf("subject-%d", i))
		for _, match := range []bool{true, false} {
			attrs := map[string]any{"eligible": match}
			initial, err := p.Evaluate("prod", "eligibility", subject, attrs, 0)
			if err != nil || initial.Candidate || initial.Match != match || initial.Bucket >= 10_000 {
				t.Fatalf("initial selection for %d = %+v, %v", i, initial, err)
			}
			for _, rung := range []uint16{10, 500, 2500, 5000, 7500, 9999, 10_000} {
				got, err := p.Evaluate("prod", "eligibility", subject, attrs, rung)
				want := Result{Match: match, Bucket: initial.Bucket, Candidate: match && initial.Bucket < rung}
				if err != nil || got != want {
					t.Fatalf("subject %d rung %d = %+v, %v, want %+v", i, rung, got, err, want)
				}
			}
		}
	}
}

func TestPredicateSemantics(t *testing.T) {
	schema := map[string]string{"enabled": "bool", "user.region": "string", "score": "int"}
	for _, tc := range []struct {
		name, expression string
		attrs            map[string]any
		match            bool
	}{
		{"blank", " \t\r\n", nil, true},
		{"precedence", "true || enabled && false", map[string]any{"enabled": true}, true},
		{"boolean and integer", "enabled && !(score < -40)", map[string]any{"enabled": true, "score": json.Number("-40")}, true},
		{"comparison", "score <= -1 && score >= -2 && score != 1 && score > -3 && score == -2", map[string]any{"score": int16(-2)}, true},
		{"integer extrema", "score >= -9223372036854775808 && score <= 9223372036854775807", map[string]any{"score": json.Number("-9223372036854775808")}, true},
		{"positive extremum", "score == 9223372036854775807", map[string]any{"score": json.Number("9223372036854775807")}, true},
		{"flat escaped text", `user.region == "東京\n\"EU\""`, map[string]any{"user.region": "東京\n\"EU\""}, true},
		{"no string normalization", `user.region == "EU"`, map[string]any{"user.region": "eu"}, false},
		{"bool comparison", "enabled == false && enabled != true", map[string]any{"enabled": false}, true},
		{"constant false", "false", nil, false},
		{"unused input ignored", `user.region != "US"`, map[string]any{"user.region": "EU", "ignored": []string{"not read"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustCompile(t, tc.expression, schema)
			got, err := p.Evaluate("prod", "eligibility", []byte("user-1"), tc.attrs, 10_000)
			want := Result{Match: tc.match, Bucket: 3984, Candidate: tc.match}
			if err != nil || got != want {
				t.Fatalf("Evaluate() = %+v, %v, want %+v", got, err, want)
			}
		})
	}
}

func TestStrictValidationBeforeNegationAndShortCircuit(t *testing.T) {
	schema := map[string]string{"blocked": "bool", "score": "int", "user.region": "string"}
	for _, tc := range []struct {
		name, expression string
		attrs            map[string]any
		want             error
	}{
		{"missing under negation", "!blocked", nil, errMissing},
		{"wrong type under negation", "!blocked", map[string]any{"blocked": "private-attribute"}, errAttribute},
		{"nil under negation", "!blocked", map[string]any{"blocked": nil}, errAttribute},
		{"skipped missing branch", "true || !(score >= 1)", nil, errMissing},
		{"skipped wrong branch", "!(false && score >= 1)", map[string]any{"score": float64(1)}, errAttribute},
		{"fractional number", "!(score == 3)", map[string]any{"score": json.Number("3.0")}, errAttribute},
		{"nondecimal form", "!(score == 3)", map[string]any{"score": json.Number("03")}, errAttribute},
		{"number overflow", "!(score == 3)", map[string]any{"score": json.Number("9223372036854775808")}, errAttribute},
		{"nested context not flat", `!(user.region == "EU")`, map[string]any{"user": map[string]any{"region": "EU"}}, errMissing},
		{"invalid UTF-8", `!(user.region == "EU")`, map[string]any{"user.region": "\xff"}, errAttribute},
		{"oversized string", `!(user.region == "EU")`, map[string]any{"user.region": strings.Repeat("a", maxString+1)}, errAttribute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustCompile(t, tc.expression, schema)
			got, err := p.Evaluate("prod", "eligibility", []byte("user-1"), tc.attrs, 10_000)
			if err != tc.want || got != (Result{}) {
				t.Fatalf("Evaluate() = %+v, %v, want zero result and %v", got, err, tc.want)
			}
		})
	}
}

func TestCompileRejectsMalformedPredicates(t *testing.T) {
	schema := map[string]string{"enabled": "bool", "region": "string", "score": "int"}
	for _, expression := range []string{
		"undeclared", "region", "true == false", "score == score", "score == true", `score >= "3"`,
		`region > "EU"`, "enabled < true", "enabled == 1", "enabled == FALSE", "enabled ||", "&& enabled",
		"(enabled", "enabled)", "()", "enabled true", "enabled | false", "score = 1", "score <= - 1",
		"score == +1", "score == 01", "score == 1e3", "score == 1.0", "score == 9223372036854775808",
		"score == -9223372036854775809", "enabled != !false", `region == "open`, "region == `EU`",
		`region == "bad\q"`, `region == "\xff"`, "region == \"\xff\"", `region in ["EU"]`, "now()", "enabled // comment",
		`region == "` + strings.Repeat("a", maxString+1) + `"`,
	} {
		if p, err := Compile(Spec{Version: 1, Expression: expression, Attributes: schema, Seed: zeroSeed}); err != errPredicate || p != nil {
			t.Errorf("Compile(%q) = %v, %v, want invalid predicate", expression, p, err)
		}
	}
}

func TestCompileEnforcesLimits(t *testing.T) {
	for _, expression := range []string{
		strings.Repeat(" ", maxExpression+1),
		strings.Repeat("(", maxDepth+1) + "true" + strings.Repeat(")", maxDepth+1),
		strings.Repeat("!", maxDepth+1) + "true",
		strings.Repeat("true && ", maxNodes/2) + "true",
	} {
		if p, err := Compile(Spec{Version: 1, Expression: expression, Seed: zeroSeed}); err != errComplexity || p != nil {
			t.Errorf("Compile(len=%d) = %v, %v, want complexity error", len(expression), p, err)
		}
	}
	mustCompile(t, strings.Repeat("!", maxDepth)+"true", nil)
	mustCompile(t, strings.Repeat("true && ", maxNodes/2-1)+"!false", nil)
	mustCompile(t, strings.Repeat(" ", maxExpression), nil)
}

func TestCompileValidatesSchemaAndSeed(t *testing.T) {
	tooMany := make(map[string]string, maxAttributes+1)
	for i := range maxAttributes + 1 {
		tooMany[fmt.Sprintf("field%d", i)] = "bool"
	}
	for _, tc := range []struct {
		name string
		spec Spec
		want error
	}{
		{"unsupported version", Spec{Version: 2, Seed: zeroSeed}, errVersion},
		{"missing seed", Spec{Version: 1}, errSeed},
		{"short seed", Spec{Version: 1, Seed: "00"}, errSeed},
		{"uppercase seed", Spec{Version: 1, Seed: strings.Repeat("A", 64)}, errSeed},
		{"nonhex seed", Spec{Version: 1, Seed: strings.Repeat("z", 64)}, errSeed},
		{"unknown type", Spec{Version: 1, Seed: zeroSeed, Attributes: map[string]string{"unused": "float"}}, errSchema},
		{"invalid path", Spec{Version: 1, Seed: zeroSeed, Attributes: map[string]string{"user..id": "string"}}, errSchema},
		{"reserved path", Spec{Version: 1, Seed: zeroSeed, Attributes: map[string]string{"true": "bool"}}, errSchema},
		{"oversized path", Spec{Version: 1, Seed: zeroSeed, Attributes: map[string]string{strings.Repeat("a", maxPath+1): "bool"}}, errSchema},
		{"oversized schema", Spec{Version: 1, Seed: zeroSeed, Attributes: tooMany}, errSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := Compile(tc.spec); err != tc.want || p != nil {
				t.Fatalf("Compile() = %v, %v, want %v", p, err, tc.want)
			}
		})
	}
}

func TestSelectorRejectsInvalidInputs(t *testing.T) {
	p := mustCompile(t, "", nil)
	tooMany := make(map[string]any, maxAttributes+1)
	for i := range maxAttributes + 1 {
		tooMany[fmt.Sprintf("field%d", i)] = true
	}
	for _, tc := range []struct {
		name, environment, plugin, subject string
		attrs                              map[string]any
		rung                               uint16
		want                               error
	}{
		{"noncanonical env", "Prod", "eligibility", "user-1", nil, 10_000, errRoutingKey},
		{"noncanonical plugin", "prod", "_plugin", "user-1", nil, 10_000, errRoutingKey},
		{"empty env", "", "eligibility", "user-1", nil, 10_000, errRoutingKey},
		{"oversized plugin", "prod", strings.Repeat("a", maxIDBytes+1), "user-1", nil, 10_000, errRoutingKey},
		{"empty subject", "prod", "eligibility", "", nil, 10_000, errSubject},
		{"oversized subject", "prod", "eligibility", strings.Repeat("a", maxSubject+1), nil, 10_000, errSubject},
		{"oversized rung", "prod", "eligibility", "user-1", nil, 10_001, errBasisPoints},
		{"oversized context", "prod", "eligibility", "user-1", tooMany, 10_000, errContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Evaluate(tc.environment, tc.plugin, []byte(tc.subject), tc.attrs, tc.rung)
			if err != tc.want || got != (Result{}) {
				t.Fatalf("Evaluate() = %+v, %v, want zero result and %v", got, err, tc.want)
			}
		})
	}
	for _, invalid := range []*Program{nil, {}} {
		if got, err := invalid.Evaluate("prod", "eligibility", []byte("user-1"), nil, 10_000); err != errProgram || got != (Result{}) {
			t.Fatalf("uncompiled Evaluate() = %+v, %v, want zero result and %v", got, err, errProgram)
		}
	}
}

func TestCompiledProgramDoesNotRetainSchema(t *testing.T) {
	schema := map[string]string{"eligible": "bool"}
	p := mustCompile(t, "eligible", schema)
	schema["eligible"] = "int"
	result, err := p.Evaluate("prod", "eligibility", []byte("user-1"), map[string]any{"eligible": true}, 10_000)
	if err != nil || !result.Candidate {
		t.Fatalf("Evaluate() after changing source schema = %+v, %v", result, err)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	p := mustCompile(b, `user.region == "EU" && eligible && score >= 42`, map[string]string{
		"user.region": "string", "eligible": "bool", "score": "int",
	})
	attrs := map[string]any{"user.region": "EU", "eligible": true, "score": int64(42)}
	subject := []byte("user-1")
	b.ReportAllocs()
	for b.Loop() {
		if got, err := p.Evaluate("prod", "eligibility", subject, attrs, 10_000); err != nil || !got.Candidate {
			b.Fatalf("Evaluate() = %+v, %v", got, err)
		}
	}
}
