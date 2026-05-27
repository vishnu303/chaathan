package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ReleaseInfo holds details about the latest available release.
type ReleaseInfo struct {
	LatestVersion string
	URL           string
	IsNewer       bool
}

// CheckForUpdates queries the GitHub Releases API to see if a newer version is available.
func CheckForUpdates(currentVersion string) (*ReleaseInfo, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://api.github.com/repos/vishnu303/chaathan/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "chaathan-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	var ghRelease struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghRelease); err != nil {
		return nil, err
	}

	info := &ReleaseInfo{
		LatestVersion: ghRelease.TagName,
		URL:           ghRelease.HTMLURL,
		IsNewer:       IsNewer(currentVersion, ghRelease.TagName),
	}

	return info, nil
}

// IsNewer compares the current version against the latest fetched version using SemVer rules.
func IsNewer(current, latest string) bool {
	if current == "dev" || current == "" || strings.HasPrefix(current, "dev-") {
		return false
	}

	currClean := cleanVersion(current)
	lateClean := cleanVersion(latest)

	currParts := strings.Split(currClean, "-")
	lateParts := strings.Split(lateClean, "-")

	currVer := currParts[0]
	lateVer := lateParts[0]

	currNums := parseVersionNumbers(currVer)
	lateNums := parseVersionNumbers(lateVer)

	// Compare major, minor, and patch numbers
	for i := 0; i < 3; i++ {
		if lateNums[i] > currNums[i] {
			return true
		}
		if lateNums[i] < currNums[i] {
			return false
		}
	}

	// Handle pre-releases (e.g. v1.0.0-beta.1)
	// Under SemVer: stable release > pre-release (e.g. v1.0.0 > v1.0.0-beta.1)
	hasCurrPre := len(currParts) > 1
	hasLatePre := len(lateParts) > 1

	if hasCurrPre && !hasLatePre {
		// Current is pre-release, latest is stable: latest is newer
		return true
	}
	if !hasCurrPre && hasLatePre {
		// Current is stable, latest is pre-release: current is newer
		return false
	}
	if hasCurrPre && hasLatePre {
		// Both are pre-releases: lexicographically compare suffix (e.g., beta.2 > beta.1)
		return lateParts[1] > currParts[1]
	}

	return false
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

func parseVersionNumbers(v string) [3]int {
	parts := strings.Split(v, ".")
	var nums [3]int
	for i := 0; i < 3; i++ {
		if i < len(parts) {
			n, err := strconv.Atoi(parts[i])
			if err == nil {
				nums[i] = n
			}
		}
	}
	return nums
}
