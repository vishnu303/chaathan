// Setup Logging
//
// Manages a per-run log file under ~/.chaathan/logs/ and provides
// captureCommandOutput to record stdout/stderr from every install command.
package setup

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/paths"
	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// Log file state
// ─────────────────────────────────────────────────────────────

var (
	setupLogFile *os.File
	setupLogMu   sync.Mutex
	setupLogPath string
)

// ─────────────────────────────────────────────────────────────
// initSetupLog — create the log file for this run
// ─────────────────────────────────────────────────────────────

func initSetupLog() {
	logDir := filepath.Join(paths.ChaathanHome(), "logs")
	os.MkdirAll(logDir, 0755)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	setupLogPath = filepath.Join(logDir, fmt.Sprintf("setup_%s.log", timestamp))

	var err error
	setupLogFile, err = os.Create(setupLogPath)
	if err != nil {
		progress.ItemInfo(fmt.Sprintf("Warning: cannot create log file: %v", err))
		return
	}

	fmt.Fprintf(setupLogFile, "=== Chaathan Setup Log ===\n")
	fmt.Fprintf(setupLogFile, "Started: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(setupLogFile, "OS: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)
}

// ─────────────────────────────────────────────────────────────
// writeSetupLog — thread-safe write to the log file
// ─────────────────────────────────────────────────────────────

func writeSetupLog(format string, args ...interface{}) {
	if setupLogFile == nil {
		return
	}
	setupLogMu.Lock()
	defer setupLogMu.Unlock()
	fmt.Fprintf(setupLogFile, format+"\n", args...)
}

// ─────────────────────────────────────────────────────────────
// captureCommandOutput — run cmd, log stdout/stderr, return error
// ─────────────────────────────────────────────────────────────

func captureCommandOutput(cmd *exec.Cmd, toolName string) error {
	var stdout, stderr bytes.Buffer

	if isVerbose() {
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	err := cmd.Run()

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
