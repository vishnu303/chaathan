package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

var (
	setupLogFile *os.File
	setupLogMu   sync.Mutex
	setupLogPath string
)

// initSetupLog creates the log file for this setup run.
func initSetupLog() {
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".chaathan", "logs")
	os.MkdirAll(logDir, 0755)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	setupLogPath = filepath.Join(logDir, fmt.Sprintf("setup_%s.log", timestamp))

	var err error
	setupLogFile, err = os.Create(setupLogPath)
	if err != nil {
		progress.ItemInfo(fmt.Sprintf("Warning: cannot create log file: %v", err))
		return
	}

	// Write header
	fmt.Fprintf(setupLogFile, "=== Chaathan Setup Log ===\n")
	fmt.Fprintf(setupLogFile, "Started: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(setupLogFile, "OS: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)
}

// writeSetupLog writes a message to the setup log file (thread-safe).
func writeSetupLog(format string, args ...interface{}) {
	if setupLogFile == nil {
		return
	}
	setupLogMu.Lock()
	defer setupLogMu.Unlock()
	fmt.Fprintf(setupLogFile, format+"\n", args...)
}

// captureCommandOutput runs a command and captures its output to the log file.
// If Verbose is true, output is also shown on screen.
func captureCommandOutput(cmd *exec.Cmd, toolName string) error {
	var stdout, stderr bytes.Buffer

	if Verbose {
		// Show on screen AND capture to buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	} else {
		// Only capture to buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	err := cmd.Run()

	// Always write to log file
	writeSetupLog("--- [%s] ---", toolName)
	writeSetupLog("Command: %s", cmd.String())
	if stdout.Len() > 0 {
		writeSetupLog("STDOUT:\n%s", stdout.String())
	}
	if stderr.Len() > 0 {
		writeSetupLog("STDERR:\n%s", stderr.String())
	}
	if err != nil {
		writeSetupLog("ERROR: %v", err)
	} else {
		writeSetupLog("STATUS: SUCCESS")
	}
	writeSetupLog("")

	return err
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install all dependency tools",
	Long: `Installs the 28+ tools required for native execution mode.

Categories:
  - Go tools:     subfinder, httpx, nuclei, katana, naabu, etc.
  - Python tools: sublist3r, subdomainizer, linkfinder, uro
  - Ruby tools:   cewl (Custom Word List generator)
  - From source:  massdns (high-performance DNS resolver)

Already-installed tools are skipped automatically.
All output is logged to ~/.chaathan/logs/setup_<timestamp>.log for debugging.

Usage:
  chaathan setup              # Install tools (parallel)
  chaathan setup --verbose    # Show live install output`,
	Run: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

// ── Tool definitions ─────────────────────────────────────────────────────────

var goTools = []struct {
	name     string
	url      string
	needsCGO bool
}{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", false},
	{"amass", "github.com/owasp-amass/amass/v4/...@latest", false},
	{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", false},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true},
	{"assetfinder", "github.com/tomnomnom/assetfinder@latest", false},
	{"gau", "github.com/lc/gau/v2/cmd/gau@latest", false},
	{"metabigor", "github.com/j3ssie/metabigor@latest", false},
	{"shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", false},
	{"anew", "github.com/tomnomnom/anew@latest", false},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", false},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest", false},
	{"ffuf", "github.com/ffuf/ffuf/v2@latest", false},
	{"gospider", "github.com/jaeles-project/gospider@latest", false},
	{"waybackurls", "github.com/tomnomnom/waybackurls@latest", false},
	{"github-subdomains", "github.com/gwen001/github-subdomains@latest", false},
	// --- Phase 3: New tools ---
	{"alterx", "github.com/projectdiscovery/alterx/cmd/alterx@latest", false},
	{"subjack", "github.com/haccer/subjack@latest", false},
	{"dalfox", "github.com/hahwul/dalfox/v2@latest", false},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", false},
	{"uncover", "github.com/projectdiscovery/uncover/cmd/uncover@latest", false},
}

var pyTools = []struct {
	name     string
	package_ string
	cmdName  string
}{
	{"cloud_enum", "git+https://github.com/initstring/cloud_enum.git", "cloud_enum.py"},
	{"sublist3r", "git+https://github.com/aboul3la/Sublist3r.git", "sublist3r.py"},
	{"linkfinder", "git+https://github.com/GerbenJavado/LinkFinder.git", "linkfinder.py"},
	{"arjun", "arjun", "arjun"},
}

// Python scripts that need manual installation (not available via pip)
var pyScripts = []struct {
	name   string
	repo   string
	script string
}{
	{"subdomainizer", "https://github.com/nsonaniya2010/SubDomainizer.git", "SubDomainizer.py"},
}

var rubyTools = []struct {
	name    string
	gemName string
}{
	{"cewl", "cewl"},
}

// ── Main setup entrypoint ────────────────────────────────────────────────────

func runSetup(cmd *cobra.Command, args []string) {
	start := time.Now()

	progress.Header("🔧 Chaathan Setup")

	// Initialize setup log file
	initSetupLog()
	if setupLogFile != nil {
		defer setupLogFile.Close()
		progress.ItemInfo(fmt.Sprintf("📝 Log file: %s", setupLogPath))
	}

	installPrerequisites()

	if _, err := exec.LookPath("go"); err != nil {
		progress.ItemFail("Go is not installed", "Please install Go 1.21+ manually")
		os.Exit(1)
	}

	var totalInstalled, totalSkipped, totalFailed int32

	// Go tools
	i, s, f := installGoToolsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	// Python tools
	i, s, f = installPythonToolsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	// Ruby tools
	i, s, f = installRubyToolsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	// MassDNS
	i, s, f = installMassDNSSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	// Write log footer
	writeSetupLog("=== Setup Complete ===")
	writeSetupLog("Duration: %s", time.Since(start).Round(time.Second))
	writeSetupLog("Installed: %d, Skipped: %d, Failed: %d", totalInstalled, totalSkipped, totalFailed)

	progress.Summary(totalInstalled, totalSkipped, totalFailed, time.Since(start))
	progress.Tip("Ensure $GOPATH/bin is in your $PATH")

	if totalFailed > 0 {
		progress.Tip(fmt.Sprintf("Check log for errors: %s", setupLogPath))
	}
}

// ── Prerequisites ────────────────────────────────────────────────────────────

func installPrerequisites() {
	progress.Section("Prerequisites", "")

	if runtime.GOOS != "linux" {
		progress.ItemInfo("Auto-install only supported on Ubuntu/Debian.")
		progress.ItemInfo("Please ensure: go, pip3, gem, git, make, gcc, libpcap-dev")
		return
	}

	type prereq struct {
		name, binary, aptPkg, dpkgPkg string
	}

	prereqs := []prereq{
		{"Go", "go", "golang-go", ""},
		{"pip3", "pip3", "python3-pip", ""},
		{"Ruby gem", "gem", "ruby-full", ""},
		{"Git", "git", "git", ""},
		{"Make", "make", "make", ""},
		{"GCC", "gcc", "gcc", ""},
		{"libpcap-dev", "", "libpcap-dev", "libpcap-dev"},
	}

	var toInstall []string
	for _, p := range prereqs {
		if isInstalled(p.binary, p.dpkgPkg) {
			progress.ItemOK(p.name)
		} else {
			progress.ItemPending(p.name)
			toInstall = append(toInstall, p.aptPkg)
		}
	}

	if len(toInstall) == 0 {
		progress.ItemInfo("All prerequisites ready")
		return
	}

	progress.ItemInfo(fmt.Sprintf("Installing %d packages via apt...", len(toInstall)))
	runSysCmd("sudo", "apt", "update", "-qq")
	if err := runSysCmd("sudo", append([]string{"apt", "install", "-y", "-qq"}, toInstall...)...); err != nil {
		progress.ItemFail("apt install", err.Error())
	} else {
		progress.ItemOK(fmt.Sprintf("%d packages installed", len(toInstall)))
	}
}

func isInstalled(binary, dpkgPkg string) bool {
	if binary != "" {
		_, err := exec.LookPath(binary)
		return err == nil
	}
	if dpkgPkg != "" {
		return exec.Command("dpkg", "-l", dpkgPkg).Run() == nil
	}
	return false
}

func runSysCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ── Go Tools ─────────────────────────────────────────────────────────────────

func installGoToolsSection() (installed, skipped, failed int) {
	// Filter already-installed tools
	var toInstall []struct {
		name     string
		url      string
		needsCGO bool
	}
	var skippedCount int
	for _, t := range goTools {
		if _, err := exec.LookPath(t.name); err == nil {
			skippedCount++
			continue
		}
		toInstall = append(toInstall, t)
	}

	detail := ""
	if skippedCount > 0 {
		detail = fmt.Sprintf("%d to install, %d already installed", len(toInstall), skippedCount)
	} else {
		detail = fmt.Sprintf("%d to install", len(toInstall))
	}
	progress.Section("Go Tools", detail)

	if len(toInstall) == 0 {
		progress.ItemInfo("Nothing to do")
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(len(toInstall))
	tracker.RunSpinner()

	var wg sync.WaitGroup
	workers := 1 // sequential: prevents OOM kills during heavy Go compilation
	sem := make(chan struct{}, workers)

	for _, t := range toInstall {
		wg.Add(1)
		go func(tool struct {
			name     string
			url      string
			needsCGO bool
		}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tracker.Start(tool.name)
			err := installGoTool(tool.name, tool.url, tool.needsCGO)
			if err != nil {
				tracker.Fail(tool.name, err.Error())
			} else {
				tracker.Complete(tool.name)
			}
		}(t)
	}

	wg.Wait()
	tracker.StopSpinner()

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

func installGoTool(name, url string, needsCGO bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "install", "-v", url)

	if needsCGO {
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	} else {
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	}

	return captureCommandOutput(cmd, name)
}

// ── Python Tools ─────────────────────────────────────────────────────────────

func installPythonToolsSection() (installed, skipped, failed int) {
	pip := "pip3"
	if _, err := exec.LookPath("pip3"); err != nil {
		if _, err := exec.LookPath("pip"); err != nil {
			progress.Section("Python Tools", "")
			progress.ItemInfo("pip not found — skipping")
			return 0, 0, 0
		}
		pip = "pip"
	}

	// Filter
	type pyTool struct {
		name, pkg, cmd string
	}
	var toInstall []pyTool
	var skippedCount int
	for _, t := range pyTools {
		if _, err := exec.LookPath(t.cmdName); err == nil {
			skippedCount++
			continue
		}
		toInstall = append(toInstall, pyTool{t.name, t.package_, t.cmdName})
	}

	// Also count scripts
	type pyScript struct {
		name, repo, script string
	}
	var scriptsToInstall []pyScript
	for _, t := range pyScripts {
		if _, err := exec.LookPath(t.name); err == nil {
			skippedCount++
			continue
		}
		scriptsToInstall = append(scriptsToInstall, pyScript{t.name, t.repo, t.script})
	}

	totalToInstall := len(toInstall) + len(scriptsToInstall)
	detail := ""
	if skippedCount > 0 {
		detail = fmt.Sprintf("%d to install, %d already installed", totalToInstall, skippedCount)
	} else {
		detail = fmt.Sprintf("%d to install", totalToInstall)
	}
	progress.Section("Python Tools", detail)

	if totalToInstall == 0 {
		progress.ItemInfo("Nothing to do")
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(totalToInstall)
	tracker.RunSpinner()

	var wg sync.WaitGroup

	// pip tools
	for _, t := range toInstall {
		wg.Add(1)
		go func(tool pyTool) {
			defer wg.Done()
			tracker.Start(tool.name)

			cmd := exec.Command(pip, "install", "--break-system-packages", tool.pkg)
			if err := captureCommandOutput(cmd, tool.name); err != nil {
				tracker.Fail(tool.name, err.Error())
			} else {
				tracker.Complete(tool.name)
			}
		}(t)
	}

	// python scripts (clone + copy)
	for _, t := range scriptsToInstall {
		wg.Add(1)
		go func(tool pyScript) {
			defer wg.Done()
			tracker.Start(tool.name)

			goPath := os.Getenv("GOPATH")
			if goPath == "" {
				home, _ := os.UserHomeDir()
				goPath = filepath.Join(home, "go")
			}
			binDir := filepath.Join(goPath, "bin")

			tempDir, err := os.MkdirTemp("", tool.name+"_*")
			if err != nil {
				tracker.Fail(tool.name, err.Error())
				return
			}
			defer os.RemoveAll(tempDir)

			cloneCmd := exec.Command("git", "clone", "--depth", "1", tool.repo, tempDir)
			if err := captureCommandOutput(cloneCmd, tool.name+" (clone)"); err != nil {
				tracker.Fail(tool.name, "clone failed")
				return
			}

			src := filepath.Join(tempDir, tool.script)
			dst := filepath.Join(binDir, tool.name)
			input, err := os.ReadFile(src)
			if err != nil {
				tracker.Fail(tool.name, "read failed")
				return
			}
			if err := os.WriteFile(dst, input, 0755); err != nil {
				tracker.Fail(tool.name, "write failed")
				return
			}
			tracker.Complete(tool.name)
		}(t)
	}

	wg.Wait()
	tracker.StopSpinner()

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

// ── Ruby Tools ───────────────────────────────────────────────────────────────

func installRubyToolsSection() (installed, skipped, failed int) {
	if _, err := exec.LookPath("gem"); err != nil {
		progress.Section("Ruby Tools", "")
		progress.ItemInfo("gem not found — skipping")
		return 0, 0, 0
	}

	var toInstall []struct{ name, gem string }
	var skippedCount int
	for _, t := range rubyTools {
		if _, err := exec.LookPath(t.name); err == nil {
			skippedCount++
			continue
		}
		toInstall = append(toInstall, struct{ name, gem string }{t.name, t.gemName})
	}

	detail := ""
	if skippedCount > 0 {
		detail = fmt.Sprintf("%d to install, %d already installed", len(toInstall), skippedCount)
	} else {
		detail = fmt.Sprintf("%d to install", len(toInstall))
	}
	progress.Section("Ruby Tools", detail)

	if len(toInstall) == 0 {
		progress.ItemInfo("Nothing to do")
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(len(toInstall))
	tracker.RunSpinner()

	var wg sync.WaitGroup
	for _, t := range toInstall {
		wg.Add(1)
		go func(tool struct{ name, gem string }) {
			defer wg.Done()
			tracker.Start(tool.name)

			// Try without sudo first
			cmd := exec.Command("gem", "install", tool.gem)
			if err := captureCommandOutput(cmd, tool.name); err != nil {
				// Retry with sudo
				cmd = exec.Command("sudo", "gem", "install", tool.gem)
				if err := captureCommandOutput(cmd, tool.name+" (sudo)"); err != nil {
					tracker.Fail(tool.name, err.Error())
					return
				}
			}
			tracker.Complete(tool.name)
		}(t)
	}

	wg.Wait()
	tracker.StopSpinner()

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

// ── MassDNS ──────────────────────────────────────────────────────────────────

func installMassDNSSection() (installed, skipped, failed int) {
	progress.Section("MassDNS", "")

	if _, err := exec.LookPath("massdns"); err == nil {
		progress.ItemOK("Already installed")
		return 0, 1, 0
	}

	if runtime.GOOS == "windows" {
		progress.ItemInfo("Windows requires manual install from github.com/blechschmidt/massdns")
		return 0, 0, 0
	}

	tracker := progress.NewTracker(3) // clone, compile, install
	tracker.RunSpinner()

	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, _ := os.UserHomeDir()
		goPath = filepath.Join(home, "go")
	}
	binDir := filepath.Join(goPath, "bin")

	tempDir, err := os.MkdirTemp("", "massdns_*")
	if err != nil {
		tracker.StopSpinner()
		progress.ItemFail("massdns", "failed to create temp dir")
		return 0, 0, 1
	}
	defer os.RemoveAll(tempDir)

	// Step 1: Clone
	tracker.Start("clone")
	massdnsClone := exec.Command("git", "clone", "--depth", "1", "https://github.com/blechschmidt/massdns.git", tempDir)
	if err := captureCommandOutput(massdnsClone, "massdns (clone)"); err != nil {
		tracker.Fail("clone", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("clone")

	// Step 2: Compile
	tracker.Start("compile")
	makeCmd := exec.Command("make", "-j", fmt.Sprintf("%d", runtime.NumCPU()))
	makeCmd.Dir = tempDir
	if err := captureCommandOutput(makeCmd, "massdns (compile)"); err != nil {
		tracker.Fail("compile", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("compile")

	// Step 3: Install
	tracker.Start("install")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	src := filepath.Join(tempDir, "bin", "massdns")
	dst := filepath.Join(binDir, "massdns")
	input, err := os.ReadFile(src)
	if err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	if err := os.WriteFile(dst, input, 0755); err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("install")

	tracker.StopSpinner()
	return 1, 0, 0
}
