package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
)

type Runner interface {
	Run(ctx context.Context, command string, args []string, opts ...Option) (string, error)
}

type NativeRunner struct {
	Verbose    bool
	MaxRetries int           // number of retries on failure (0 = no retry)
	RetryDelay time.Duration // delay between retries
}

type DockerRunner struct {
	Verbose    bool
	MaxRetries int
	RetryDelay time.Duration
}

type RunOptions struct {
	Dir     string
	Env     []string
	Timeout time.Duration // per-tool timeout (0 = use context timeout)
}

type Option func(*RunOptions)

func WithDir(dir string) Option {
	return func(o *RunOptions) {
		o.Dir = dir
	}
}

func WithTimeout(d time.Duration) Option {
	return func(o *RunOptions) {
		o.Timeout = d
	}
}

// WithEnv appends environment variables (in "KEY=VALUE" form) to the
// command's environment. The variables are added on top of os.Environ().
func WithEnv(env ...string) Option {
	return func(o *RunOptions) {
		o.Env = append(o.Env, env...)
	}
}

// ── Shared retry logic ──────────────────────────────────────────────────────

// runOnceFunc executes a single attempt and returns (stdout, error).
type runOnceFunc func(ctx context.Context) (string, error)

// retryRun executes fn up to maxRetries+1 times, with delay between attempts.
// It respects context cancellation and logs retries via logger.Warning.
func retryRun(ctx context.Context, command string, maxRetries int, retryDelay time.Duration, fn runOnceFunc) (string, error) {
	maxAttempts := maxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		output, err := fn(ctx)
		if err == nil {
			return output, nil
		}

		lastErr = err

		// Don't retry on context cancellation (user pressed Ctrl+C)
		if ctx.Err() != nil {
			return output, fmt.Errorf("cancelled: %w", err)
		}

		// Log retry
		if attempt < maxAttempts {
			delay := retryDelay
			if delay == 0 {
				delay = 3 * time.Second
			}
			logger.Warning("[Retry %d/%d] %s failed: %v — retrying in %s...",
				attempt, maxRetries, command, err, delay)
			time.Sleep(delay)
		}
	}

	return "", lastErr
}

// ── NativeRunner ────────────────────────────────────────────────────────────

func (r *NativeRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
	options := &RunOptions{}
	for _, o := range opts {
		o(options)
	}

	// Apply per-tool timeout if configured
	runCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	return retryRun(runCtx, command, r.MaxRetries, r.RetryDelay, func(rCtx context.Context) (string, error) {
		return r.runOnce(rCtx, command, args, options)
	})
}

func (r *NativeRunner) runOnce(ctx context.Context, command string, args []string, options *RunOptions) (string, error) {
	cmd := exec.CommandContext(ctx, command, args...)

	if options.Dir != "" {
		cmd.Dir = options.Dir
	}
	if len(options.Env) > 0 {
		cmd.Env = append(os.Environ(), options.Env...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if r.Verbose {
		logger.Command(fmt.Sprintf("%s %s", command, strings.Join(args, " ")))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := startAndWait(ctx, cmd)
	if err != nil {
		if r.Verbose {
			logger.Debug("CMD Error: %v | Stderr: %s", err, stderr.String())
		}
		// Return stderr as error description if available
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%v: %s", err, stderr.String())
		}
		return stdout.String(), err
	}

	return stdout.String(), nil
}

// ── DockerRunner ────────────────────────────────────────────────────────────

func (r *DockerRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
	options := &RunOptions{}
	for _, o := range opts {
		o(options)
	}

	// Apply per-tool timeout if configured
	runCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	return retryRun(runCtx, command, r.MaxRetries, r.RetryDelay, func(rCtx context.Context) (string, error) {
		return r.runOnce(rCtx, command, args, options)
	})
}

func (r *DockerRunner) runOnce(ctx context.Context, command string, args []string, options *RunOptions) (string, error) {
	image := getDockerImage(command)

	// We do NOT use -t (tty) here because it messes up output capturing usually
	dockerArgs := []string{"run", "--rm", "-i"}

	// Mount the working directory
	if options.Dir != "" {
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/data", options.Dir))
	} else {
		pwd, _ := os.Getwd()
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/data", pwd))
	}
	dockerArgs = append(dockerArgs, "-w", "/data")

	// Pass environment variables
	for _, env := range options.Env {
		dockerArgs = append(dockerArgs, "-e", env)
	}

	dockerArgs = append(dockerArgs, image)

	if !isEntrypointImage(command) {
		switch command {
		// Handle cases where command needs to be passed to container
		default:
			dockerArgs = append(dockerArgs, command)
		}
	}

	dockerArgs = append(dockerArgs, args...)

	if r.Verbose {
		logger.Command(fmt.Sprintf("DOCKER %s", strings.Join(dockerArgs, " ")))
	}

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := startAndWait(ctx, cmd)
	if err != nil {
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%v: %s", err, stderr.String())
		}
		return stdout.String(), err
	}

	return stdout.String(), nil
}

// ── Shared helpers ──────────────────────────────────────────────────────────

// startAndWait ensures context cancellation terminates the entire process group,
// not just the top-level command. Many recon tools spawn child processes, and
// skip/cancel must tear those down so the workflow can advance immediately.
func startAndWait(ctx context.Context, cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		killProcessGroup(cmd)
		
		// Wait at most 2 seconds for process and its I/O to cleanly exit.
		// If child processes inherited stdout/stderr and didn't die from the group kill,
		// Wait() would block indefinitely. This prevents the hang.
		select {
		case err := <-done:
			if err == nil {
				return ctx.Err()
			}
			return err
		case <-time.After(2 * time.Second):
			return ctx.Err()
		}
	}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	// Negative PID targets the entire process group created via Setpgid.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// ── Docker image registry (F30) ─────────────────────────────────────────────
//
// Single lookup table for tool → Docker image + entry-point flag.
// Tools without an official Docker image use "alpine" as a fallback,
// meaning they won't work in Docker mode. These are tagged with a comment
// so operators can supply custom images via config override.

type dockerImageInfo struct {
	Image      string // Docker Hub image name
	Entrypoint bool   // true if the image uses ENTRYPOINT (don't pass tool name)
}

var dockerImages = map[string]dockerImageInfo{
	// Project Discovery tools — all use ENTRYPOINT
	"subfinder":   {"projectdiscovery/subfinder", true},
	"nuclei":      {"projectdiscovery/nuclei", true},
	"httpx":       {"projectdiscovery/httpx", true},
	"naabu":       {"projectdiscovery/naabu", true},
	"dnsx":        {"projectdiscovery/dnsx", true},
	"katana":      {"projectdiscovery/katana", true},
	"tlsx":        {"projectdiscovery/tlsx", true},
	"uncover":     {"projectdiscovery/uncover", true},
	"shuffledns":  {"projectdiscovery/shuffledns", true},

	// Third-party tools with ENTRYPOINT
	"amass":       {"caffix/amass", true},
	"ffuf":        {"ffuf/ffuf", true},
	"dalfox":      {"hahwul/dalfox", true},
	"arjun":       {"s0md3v/arjun", true},
	"GoLinkFinder": {"alpine", false}, // no official image; go binary compiled from source

	// Third-party tools WITHOUT ENTRYPOINT (need command passed)
	"assetfinder":      {"tomnomnom/assetfinder", false},
	"gau":              {"sxcurity/gau", false},
	"waybackurls":      {"sxcurity/waybackurls", false},
	"metabigor":        {"j3ssie/metabigor", false},
	"gospider":         {"jaeles-project/gospider", false},
	"github-subdomains": {"gwen001/github-subdomains", false},

	// No official Docker image — alpine fallback (won't work without custom image)
	"hakrawler":      {"hakluke/hakrawler", true}, // reads stdin; official ENTRYPOINT image
	"sublist3r":     {"alpine", false}, // Python script — no official image
	"cloud_enum":    {"alpine", false}, // Python script — no official image
	"massdns":       {"alpine", false}, // compiled from source
	"anew":          {"alpine", false}, // tiny Go binary — unlikely to need Docker
	"gf":            {"alpine", false}, // tiny Go binary — unlikely to need Docker
}

func getDockerImage(tool string) string {
	if info, ok := dockerImages[tool]; ok {
		return info.Image
	}
	return "alpine"
}

func isEntrypointImage(tool string) bool {
	if info, ok := dockerImages[tool]; ok {
		return info.Entrypoint
	}
	return false
}


// NewWithRetry creates a runner with retry logic.
func NewWithRetry(mode string, verbose bool, maxRetries int, retryDelay time.Duration) Runner {
	if mode == "docker" {
		return &DockerRunner{Verbose: verbose, MaxRetries: maxRetries, RetryDelay: retryDelay}
	}
	return &NativeRunner{Verbose: verbose, MaxRetries: maxRetries, RetryDelay: retryDelay}
}

