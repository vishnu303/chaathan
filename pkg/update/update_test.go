package update

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		// Basic upgrades
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.0", "v2.0.0", true},
		{"1.0.0", "v1.0.1", true},
		{"v1.0.0", "1.0.1", true},

		// Same versions
		{"v1.0.0", "v1.0.0", false},
		{"v2.1.3", "v2.1.3", false},

		// Downgrades / Older latest
		{"v1.1.0", "v1.0.0", false},
		{"v1.0.1", "v1.0.0", false},
		{"v2.0.0", "v1.0.0", false},

		// Pre-releases
		{"v1.0.0-beta.1", "v1.0.0", true},
		{"v1.0.0-rc.1", "v1.0.0", true},
		{"v1.0.0", "v1.0.0-beta.1", false},
		{"v1.0.0-beta.1", "v1.0.0-beta.2", true},
		{"v1.0.0-beta.2", "v1.0.0-beta.1", false},

		// Dev builds (should not alert for new versions to prevent dev environment spam)
		{"dev", "v1.0.0", false},
		{"dev-dirty", "v1.0.0", false},
		{"", "v1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.current+" vs "+tt.latest, func(t *testing.T) {
			got := IsNewer(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("IsNewer(%q, %q) = %v; want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}
