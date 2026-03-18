package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
	Long: `Installs the tools required for native execution mode.

Categories:
  - Go tools:     subfinder, httpx, nuclei, katana, naabu, etc.
  - Python tools: sublist3r, subdomainizer, linkfinder, arjun
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
	name string
	url  string
}{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"amass", "github.com/owasp-amass/amass/v4/...@latest"},
	{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
	{"assetfinder", "github.com/tomnomnom/assetfinder@latest"},
	{"gau", "github.com/lc/gau/v2/cmd/gau@latest"},
	{"metabigor", "github.com/j3ssie/metabigor@latest"},
	{"shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
	{"anew", "github.com/tomnomnom/anew@latest"},
	{"gf", "github.com/tomnomnom/gf@latest"},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest"},
	{"ffuf", "github.com/ffuf/ffuf/v2@latest"},
	{"gospider", "github.com/jaeles-project/gospider@latest"},
	{"waybackurls", "github.com/tomnomnom/waybackurls@latest"},
	{"github-subdomains", "github.com/gwen001/github-subdomains@latest"},
	{"subjack", "github.com/haccer/subjack@latest"},
	{"dalfox", "github.com/hahwul/dalfox/v2@latest"},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
	{"uncover", "github.com/projectdiscovery/uncover/cmd/uncover@latest"},
}

var pyTools = []struct {
	name     string
	package_ string
	cmdName  string
	module   string
}{
	{"cloud_enum", "git+https://github.com/initstring/cloud_enum.git", "cloud_enum.py", "cloud_enum"},
	{"sublist3r", "git+https://github.com/aboul3la/Sublist3r.git", "sublist3r.py", "sublist3r"},
	{"linkfinder", "git+https://github.com/GerbenJavado/LinkFinder.git", "linkfinder.py", "linkfinder"},
	{"arjun", "arjun", "arjun", "arjun"},
}

// Python scripts that need manual installation (not available via pip)
var pyScripts = []struct {
	name   string
	repo   string
	script string
}{
	{"subdomainizer", "https://github.com/nsonaniya2010/SubDomainizer.git", "SubDomainizer.py"},
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

	// gf patterns
	i, s, f = installGFPatternsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	// Python tools
	i, s, f = installPythonToolsSection()
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
		name string
		url  string
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
		go func(tool struct{ name, url string }) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tracker.Start(tool.name)
			if err := installGoTool(tool.name, tool.url); err != nil {
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

func installGoTool(name, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "install", "-v", url)
	return captureCommandOutput(cmd, name)
}

func installGFPatternsSection() (installed, skipped, failed int) {
	progress.Section("gf Patterns", "installing local pattern pack for step 19 URL filtering")

	if _, err := exec.LookPath("gf"); err != nil {
		progress.ItemInfo("gf binary not installed yet — skipping pattern install")
		return 0, 1, 0
	}

	home, err := os.UserHomeDir()
	if err != nil {
		progress.ItemFail("gf patterns", "cannot determine home directory")
		return 0, 0, 1
	}

	gfDir := filepath.Join(home, ".gf")
	if err := os.MkdirAll(gfDir, 0755); err != nil {
		progress.ItemFail("gf patterns", err.Error())
		return 0, 0, 1
	}

	patterns := map[string]map[string][]string{
		"ssrf": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](url|uri|path|dest|destination|redirect|redirect_uri|redir|return|return_url|next|data|site|domain|feed|host|port|to|out|view|continue|callback|reference)=)`,
			},
		},
		"redirect": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](redirect|redirect_url|redirect_uri|redir|return|return_to|return_url|next|continue|dest|destination|callback)=)`,
			},
		},
		"lfi": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](file|filename|filepath|path|page|include|template|doc|folder|root|pg)=)`,
			},
		},
		"sqli": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](id|ids|user|user_id|uid|account|number|order|sort|group|search|query|filter|report|category|item|product)=)`,
			},
		},
		"xss": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](q|query|search|s|lang|keyword|term|text|message|comment|redirect|url|next|return)=)`,
			},
		},
		"rce": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](cmd|exec|command|execute|ping|query|code|do|daemon|process|upload|download)=)`,
			},
		},
		"idor": {
			"flags": {"-iE"},
			"patterns": {
				`(/(users|user|accounts|orders|order|projects|project|files|file|documents|document|invoices|invoice|tickets|ticket|profiles|profile|messages|message|payments|payment|api)/[^/?#]+)`,
				`([?&](id|user_id|account_id|order_id|project_id|file_id|doc_id|invoice_id|ticket_id|profile_id|message_id|payment_id|uid)=)`,
			},
		},
		"debug_logic": {
			"flags": {"-iE"},
			"patterns": {
				`(/(debug|test|staging|dev|console|actuator|swagger|openapi|internal|admin|config|health|metrics))`,
			},
		},
	}

	installedCount := 0
	skippedCount := 0
	for name, pattern := range patterns {
		path := filepath.Join(gfDir, name+".json")
		if _, err := os.Stat(path); err == nil {
			skippedCount++
			continue
		}

		data, err := json.MarshalIndent(pattern, "", "  ")
		if err != nil {
			progress.ItemFail(name, "failed to marshal pattern")
			failed++
			continue
		}
		if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			progress.ItemFail(name, err.Error())
			failed++
			continue
		}
		installedCount++
	}

	if installedCount > 0 {
		progress.ItemOK(fmt.Sprintf("%d gf patterns installed", installedCount))
	}
	if installedCount == 0 && failed == 0 {
		progress.ItemInfo("gf pattern pack already present")
	}

	return installedCount, skippedCount, failed
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
		name, pkg, cmd, module string
	}
	var toInstall []pyTool
	var skippedCount int
	for _, t := range pyTools {
		if pythonToolInstalled(t.name, t.cmdName, t.module) {
			_ = ensurePythonToolShim(t.name, t.module)
			skippedCount++
			continue
		}
		toInstall = append(toInstall, pyTool{t.name, t.package_, t.cmdName, t.module})
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
			} else if err := ensurePythonToolShim(tool.name, tool.module); err != nil {
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

func pythonToolInstalled(name, cmdName, module string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	if cmdName != "" {
		if _, err := exec.LookPath(cmdName); err == nil {
			return true
		}
	}
	if module != "" && pythonModuleInstalled(module) {
		return true
	}
	return false
}

func pythonModuleInstalled(module string) bool {
	if module == "" {
		return false
	}
	cmd := exec.Command("python3", "-c", "import "+module)
	return cmd.Run() == nil
}

func ensurePythonToolShim(name, module string) error {
	if name == "" || module == "" {
		return nil
	}
	if _, err := exec.LookPath(name); err == nil {
		return nil
	}
	if !pythonModuleInstalled(module) {
		return fmt.Errorf("%s module is not importable after install", module)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}

	shimPath := filepath.Join(binDir, name)
	shim := fmt.Sprintf("#!/usr/bin/env bash\npython3 -m %s \"$@\"\n", module)
	return os.WriteFile(shimPath, []byte(shim), 0755)
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
