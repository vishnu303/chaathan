package progress_test

import (
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
)

func TestProgressHelpers(t *testing.T) {
	// Simple tests to make sure display helpers don't crash
	progress.Header("Setup Tools")
	progress.Section("System Tools", "Checking path dependencies")
	progress.ItemOK("go")
	progress.ItemFail("massdns", "binary not found")
	progress.ItemPending("python3")
	progress.ItemInfo("Using BlackArch repositories")
	progress.Summary(1, 0, 1, 15*time.Second)
	progress.Tip("Add ~/.local/bin to PATH")
}

func TestProgressTracker(t *testing.T) {
	tracker := progress.NewTracker(3)
	if tracker == nil {
		t.Fatal("expected NewTracker to return non-nil")
	}

	tracker.Start("nuclei")
	tracker.Start("subfinder")

	tracker.Complete("subfinder")
	tracker.Fail("nuclei", "failed to extract package")
	tracker.Skip("assetfinder")

	installed, skipped, failed := tracker.Stats()
	if installed != 1 {
		t.Errorf("expected 1 installed, got %d", installed)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", skipped)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}

	// Spinner tests
	tracker.RunSpinner()
	time.Sleep(100 * time.Millisecond)
	tracker.StopSpinner()
}
