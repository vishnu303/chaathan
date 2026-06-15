// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/progress"
)

// SetupLogger encapsulates file-based logging for the installation and setup processes.
// It is thread-safe and manages raw stdout/stderr capture from external commands.
type SetupLogger struct {
	file *os.File
	mu   sync.Mutex
	path string
}

// NewSetupLogger creates a new log file in ~/.chaathan/logs/ with a timestamp.
// If file creation fails, it returns a logger that gracefully does not write anywhere, along with the error.
func NewSetupLogger() (*SetupLogger, error) {
	logDir := paths.LogsDir()
	if err := os.MkdirAll(logDir, 0755); err != nil {
		progress.ItemInfo(fmt.Sprintf("Warning: cannot create logs directory: %v", err))
		return &SetupLogger{}, err
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logPath := filepath.Join(logDir, fmt.Sprintf("setup_%s.log", timestamp))

	file, err := os.Create(logPath)
	if err != nil {
		progress.ItemInfo(fmt.Sprintf("Warning: cannot create log file: %v", err))
		return &SetupLogger{}, err
	}

	logger := &SetupLogger{
		file: file,
		path: logPath,
	}

	logger.Write("=== Chaathan Setup Log ===")
	logger.Write("Started: %s", time.Now().Format(time.RFC3339))
	logger.Write("OS: %s/%s", runtime.GOOS, runtime.GOARCH)
	logger.Write("")

	return logger, nil
}

// Path returns the absolute file path of the setup log file.
func (l *SetupLogger) Path() string {
	return l.path
}

// Close closes the underlying log file handle.
func (l *SetupLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Write appends a formatted line to the log file in a thread-safe manner.
func (l *SetupLogger) Write(format string, args ...any) {
	if l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.file, format+"\n", args...)
}

// CaptureCommandOutput executes the command and streams/logs its output.
// If verbose is true, outputs are piped live to the console in addition to the log file.
func (l *SetupLogger) CaptureCommandOutput(cmd *exec.Cmd, toolName string, verbose bool) error {
	var stdout, stderr bytes.Buffer

	if verbose {
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	err := cmd.Run()

	l.Write("--- [%s] ---", toolName)
	l.Write("Command: %s", cmd.String())
	if stdout.Len() > 0 {
		l.Write("STDOUT:\n%s", stdout.String())
	}
	if stderr.Len() > 0 {
		l.Write("STDERR:\n%s", stderr.String())
	}
	if err != nil {
		l.Write("ERROR: %v", err)
		l.Write("")
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	l.Write("STATUS: SUCCESS")
	l.Write("")

	return nil
}
