package logger

import (
	"testing"
)

func TestSmartStepHeaderIncrement(t *testing.T) {
	InitScanUI(23)

	// 1. First step call: increments to 1
	StepHeader("Step 1: Passive Recon")
	if currentStep != 1 {
		t.Errorf("expected step 1, got %d", currentStep)
	}

	// 2. Second step call (different step): increments to 2
	StepHeader("Step 2: Active Subdomain Enumeration (Amass)")
	if currentStep != 2 {
		t.Errorf("expected step 2, got %d", currentStep)
	}

	// 3. Skip call for same step: should NOT increment (stays at 2)
	StepHeader("Step 2: Skipping Amass (--skip-amass)")
	if currentStep != 2 {
		t.Errorf("expected step 2 to remain, got %d", currentStep)
	}

	// 4. Next step (different step): increments to 3
	StepHeader("Step 3: GitHub Subdomain Discovery")
	if currentStep != 3 {
		t.Errorf("expected step 3, got %d", currentStep)
	}

	// 5. Alternate/skip call for same step: should NOT increment (stays at 3)
	StepHeader("Step 3: Skipping GitHub Recon (no token provided)")
	if currentStep != 3 {
		t.Errorf("expected step 3 to remain, got %d", currentStep)
	}

	// 6. Non-step prefix call: should increment (since prefix is "")
	StepHeader("Some random header")
	if currentStep != 4 {
		t.Errorf("expected step 4, got %d", currentStep)
	}
}
