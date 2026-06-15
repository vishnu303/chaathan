package tools_test

import (
	"context"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/pkg/tools"
)

type DummyRunner struct {
	LastCmd  string
	LastArgs []string
}

func (d *DummyRunner) Run(ctx context.Context, command string, args []string, opts ...runner.Option) (string, error) {
	d.LastCmd = command
	d.LastArgs = args
	return "dummy output", nil
}

func TestToolBoxOptionsAndHelpers(t *testing.T) {
	dr := &DummyRunner{}
	tb := tools.New(dr)

	if tb == nil {
		t.Fatal("expected non-nil ToolBox")
	}

	// 1. Random User-Agent
	ua := tools.RandomUA()
	if len(ua) == 0 {
		t.Error("expected non-empty User-Agent")
	}

	// 2. Custom Auth configuration
	tb.WithCustomAuth("cookie_val", []string{"Auth: token_val"})
	if tb.CustomCookie != "cookie_val" {
		t.Errorf("expected cookie_val, got %q", tb.CustomCookie)
	}
	if len(tb.CustomHeaders) != 1 || tb.CustomHeaders[0] != "Auth: token_val" {
		t.Errorf("unexpected custom headers: %v", tb.CustomHeaders)
	}

	// 3. Configurations attaching
	gen := &config.GeneralConfig{UARotation: true, Proxy: "http://proxy"}
	tb.WithGeneral(gen)
	tb.WithRateLimits(&config.RateLimitConfig{GlobalRPS: 100})
	tb.WithAPIKeys(&config.APIKeysConfig{GitHub: "github_token"})

	// 4. Test tool invocation (Subfinder)
	ctx := context.Background()
	err := tb.RunSubfinder(ctx, "target.com", "out.txt")
	if err != nil {
		t.Fatalf("unexpected error running Subfinder: %v", err)
	}

	if dr.LastCmd != "subfinder" {
		t.Errorf("expected command 'subfinder', got %q", dr.LastCmd)
	}

	// Check arguments contains target domain
	argsJoined := strings.Join(dr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-d target.com") {
		t.Errorf("expected arguments to contain domain target.com, got %q", argsJoined)
	}
}
