// Package plugins packs the example's real Lua plugins with the go-plg CLI.
package plugins

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"

	"github.com/heynemann/go-plg-s3-registry/examples/rewards/contract"
)

//go:embed plugin.yaml tests/example.yaml v1/plugin.lua v2/plugin.lua
var files embed.FS

// Commits records the clean author revisions captured by `plg pack`.
type Commits struct {
	First  string `json:"first_commit"`
	Second string `json:"second_commit"`
}

// Pack writes first.plg and second.plg into out without overwriting files. It
// uses a temporary author checkout and a local Go proxy for the sample contract.
func Pack(ctx context.Context, plg, out string) (Commits, error) {
	out, err := filepath.Abs(out)
	if err != nil {
		return Commits{}, err
	}
	if err = os.MkdirAll(out, 0o700); err != nil {
		return Commits{}, err
	}
	tmp, err := os.MkdirTemp(out, ".author-")
	if err != nil {
		return Commits{}, err
	}
	defer os.RemoveAll(tmp)
	if plg == "" {
		plg = filepath.Join(tmp, "plg")
		if _, err = run(ctx, "", nil, "go", "build", "-o", plg, "github.com/heynemann/go-plg/cmd/plg"); err != nil {
			return Commits{}, err
		}
	} else {
		plg, err = exec.LookPath(plg)
		if err != nil {
			return Commits{}, err
		}
		plg, err = filepath.Abs(plg)
		if err != nil {
			return Commits{}, err
		}
	}
	proxy, author := filepath.Join(tmp, "proxy"), filepath.Join(tmp, "checkout")
	if err = writeProxy(proxy, filepath.Join(tmp, "source")); err != nil {
		return Commits{}, fmt.Errorf("prepare sample contract: %w", err)
	}
	if err = os.Mkdir(author, 0o700); err != nil {
		return Commits{}, err
	}
	proxyURL := (&url.URL{Scheme: "file", Path: proxy}).String()
	cmdEnv := append(cleanGitEnv(), "GOPROXY="+proxyURL, "GOMODCACHE="+filepath.Join(tmp, "modcache"), "GOFLAGS=-modcacherw", "GONOSUMDB="+contract.Module,
		"GOPRIVATE=", "GONOPROXY=none", "GOWORK=off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if _, err = run(ctx, author, cmdEnv, "git", "init", "-q", "--template="); err != nil {
		return Commits{}, err
	}
	if _, err = run(ctx, author, cmdEnv, plg, "init", "-lang", "lua", "-implements", contract.Module+".Rule@"+contract.Version, "eligibility"); err != nil {
		return Commits{}, err
	}
	plugin := filepath.Join(author, "eligibility")
	for _, name := range []string{"plugin.yaml", "tests/example.yaml"} {
		if err = writeFixture(plugin, name, name); err != nil {
			return Commits{}, err
		}
	}
	var commits Commits
	for i, version := range []string{"v1", "v2"} {
		if err = writeFixture(plugin, version+"/plugin.lua", "plugin.lua"); err != nil {
			return Commits{}, err
		}
		if i == 0 {
			if _, err = run(ctx, author, cmdEnv, plg, "validate", "-color", "never", "eligibility"); err != nil {
				return Commits{}, err
			}
		}
		if _, err = run(ctx, author, cmdEnv, "git", "add", "--all"); err != nil {
			return Commits{}, err
		}
		if _, err = run(ctx, author, cmdEnv, "git", "-c", "user.name=Rewards Demo", "-c", "user.email=demo@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", version); err != nil {
			return Commits{}, err
		}
		commit, err := run(ctx, author, cmdEnv, "git", "rev-parse", "HEAD")
		if err != nil {
			return Commits{}, err
		}
		if i == 0 {
			commits.First = strings.TrimSpace(commit)
		} else {
			commits.Second = strings.TrimSpace(commit)
		}
		if _, err = run(ctx, author, cmdEnv, plg, "pack", "-color", "never", "-o", filepath.Join(tmp, version), "eligibility"); err != nil {
			return Commits{}, err
		}
	}
	first := filepath.Join(out, "first.plg")
	if err = os.Link(filepath.Join(tmp, "v1", "eligibility.plg"), first); err != nil {
		return Commits{}, err
	}
	if err = os.Link(filepath.Join(tmp, "v2", "eligibility.plg"), filepath.Join(out, "second.plg")); err != nil {
		return Commits{}, errors.Join(err, os.Remove(first))
	}
	return commits, nil
}

func writeProxy(proxy, src string) error {
	versionDir := filepath.Join(proxy, contract.Module, "@v")
	for _, folder := range []string{src, versionDir} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			return err
		}
	}
	mod := []byte("module " + contract.Module + "\n\ngo 1.27\n")
	code, err := contract.Source()
	if err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{
		{filepath.Join(src, "go.mod"), mod}, {filepath.Join(src, "contract.go"), code},
		{filepath.Join(versionDir, contract.Version+".mod"), mod},
		{filepath.Join(versionDir, contract.Version+".info"), fmt.Appendf(nil, `{"Version":%q,"Time":"2020-01-01T00:00:00Z"}`, contract.Version)},
	} {
		if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
			return err
		}
	}
	archive, err := os.Create(filepath.Join(versionDir, contract.Version+".zip"))
	if err != nil {
		return err
	}
	return errors.Join(zip.CreateFromDir(archive, module.Version{Path: contract.Module, Version: contract.Version}, src), archive.Close())
}

func writeFixture(plugin, source, target string) error {
	data, err := files.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(plugin, target), data, 0o600)
}

func cleanGitEnv() []string {
	env := os.Environ()
	n := 0
	for _, entry := range env {
		if !strings.HasPrefix(entry, "GIT_") {
			env[n] = entry
			n++
		}
	}
	return env[:n]
}

func run(ctx context.Context, dir string, env []string, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", filepath.Base(binary), args[0], err, out)
	}
	return string(out), nil
}
