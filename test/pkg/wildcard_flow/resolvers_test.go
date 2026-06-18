package wildcard_flow_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
	"github.com/vishnu303/chaathan/utils"
)

func TestSetupResolvers_DefaultCreation(t *testing.T) {
	// Create temporary directory for testing
	tempResult, err := os.MkdirTemp("", "chaathan-result-*")
	if err != nil {
		t.Fatalf("Failed to create temp result: %v", err)
	}
	defer os.RemoveAll(tempResult)

	// Ensure intermediate files directory exists
	interDir := filepath.Join(tempResult, "intermediate_files")
	if err := os.MkdirAll(interDir, 0755); err != nil {
		t.Fatalf("Failed to create intermediate dir: %v", err)
	}

	c := &wildcard_flow.Ctx{
		RunConfig: wildcard_flow.RunConfig{
			ResolversPath: "",
		},
		F: wildcard_flow.Files{
			ConsolidatedSubs: filepath.Join(interDir, "all_subdomains.txt"),
		},
	}

	// Run SetupResolvers
	err = c.SetupResolvers()
	if err != nil {
		t.Fatalf("SetupResolvers failed: %v", err)
	}

	// Verify c.ResolversPath was updated to the intermediate directory
	expectedDest := filepath.Join(interDir, "resolvers.txt")
	if c.ResolversPath != expectedDest {
		t.Errorf("Expected ResolversPath to be %s, got %s", expectedDest, c.ResolversPath)
	}

	// Verify file was created in the intermediate directory
	if !utils.FileExists(expectedDest) {
		t.Fatalf("Expected resolvers file at: %s", expectedDest)
	}

	destData, err := os.ReadFile(expectedDest)
	if err != nil {
		t.Fatalf("Failed to read resolvers: %v", err)
	}
	if !strings.Contains(string(destData), "1.1.1.1") {
		t.Errorf("Expected resolvers to contain 1.1.1.1, got: %s", string(destData))
	}
}

func TestSetupResolvers_CustomProvided(t *testing.T) {
	tempResult, err := os.MkdirTemp("", "chaathan-result-*")
	if err != nil {
		t.Fatalf("Failed to create temp result: %v", err)
	}
	defer os.RemoveAll(tempResult)

	interDir := filepath.Join(tempResult, "intermediate_files")
	if err := os.MkdirAll(interDir, 0755); err != nil {
		t.Fatalf("Failed to create intermediate dir: %v", err)
	}

	// Create a custom resolvers file
	customFile := filepath.Join(tempResult, "my_custom_resolvers.txt")
	customContent := "8.8.8.8\n8.8.4.4\n"
	if err := os.WriteFile(customFile, []byte(customContent), 0644); err != nil {
		t.Fatalf("Failed to write custom resolvers: %v", err)
	}

	c := &wildcard_flow.Ctx{
		RunConfig: wildcard_flow.RunConfig{
			ResolversPath: customFile,
		},
		F: wildcard_flow.Files{
			ConsolidatedSubs: filepath.Join(interDir, "all_subdomains.txt"),
		},
	}

	// Run SetupResolvers
	err = c.SetupResolvers()
	if err != nil {
		t.Fatalf("SetupResolvers failed: %v", err)
	}

	// Verify c.ResolversPath was left unchanged
	if c.ResolversPath != customFile {
		t.Errorf("Expected ResolversPath to be left unchanged as %s, got %s", customFile, c.ResolversPath)
	}
}
