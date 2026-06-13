package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// MergeAndDeduplicate reads multiple input files, merges their content,
// deduplicates lines, sorts them, and writes to an output file.
func MergeAndDeduplicate(inputFiles []string, outputFile string) error {
	uniqueLines := make(map[string]bool)

	for _, file := range inputFiles {
		if err := readFileInto(file, uniqueLines); err != nil {
			return err
		}
	}

	// Sort keys
	result := make([]string, 0, len(uniqueLines))
	for line := range uniqueLines {
		result = append(result, line)
	}
	sort.Strings(result)

	// Write to output
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range result {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// readFileInto reads non-empty lines from a single file into the dest map.
// The file handle is closed when this function returns, avoiding FD leaks
// that occur when defer is used inside a loop.
func readFileInto(path string, dest map[string]bool) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // missing files are silently skipped
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			dest[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed reading %s: %w", path, err)
	}
	return nil
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// CountFileLines returns the number of non-empty lines in a file
func CountFileLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count, scanner.Err()
}

// FilterFileLines reads a file, keeps only lines where keep() returns true,
// and writes the result back in place. Empty lines are always dropped.
func FilterFileLines(filePath string, keep func(string) bool) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	var kept []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && keep(line) {
			kept = append(kept, line)
		}
	}
	if err := scanner.Err(); err != nil {
		file.Close()
		return err
	}
	file.Close()

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range kept {
		w.WriteString(line)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// SanitizeURLFile reads a URL file, cleans each line (unescaping unicode,
// stripping non-URL lines), and writes the result back in place.
// This prevents downstream tools (Nuclei, Dalfox, httpx) from receiving
// malformed URLs that contain literal \uXXXX sequences or GoSpider tags.
func SanitizeURLFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	var cleaned []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Unescape \\uXXXX → \uXXXX → actual character
		line = unescapeUnicodeURL(line)

		// Strip trailing backslashes left over from JS string extraction
		line = strings.TrimRight(line, "\\")

		// Skip non-URL lines (GoSpider tags, relative paths, bare words)
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}

		if !seen[line] {
			seen[line] = true
			cleaned = append(cleaned, line)
		}
	}
	if err := scanner.Err(); err != nil {
		file.Close()
		return err
	}
	file.Close()

	sort.Strings(cleaned)
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range cleaned {
		w.WriteString(line)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// unescapeUnicodeURL replaces literal \uXXXX sequences with their
// actual characters. GoLinkFinder extracts URLs from JavaScript source
// where & is encoded as \u0026, producing URLs like:
//   http://example.com/?a=1\u0026b=2
// Tools like Nuclei and Dalfox need the real & character.
func unescapeUnicodeURL(s string) string {
	// Handle double-escaped \\u first
	s = strings.ReplaceAll(s, "\\\\u", "\\u")

	// Fast path: no unicode escapes
	if !strings.Contains(s, "\\u") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			// Try to parse 4 hex digits after \u
			hex := s[i+2 : i+6]
			if r, ok := parseHex4(hex); ok {
				b.WriteRune(r)
				i += 5 // skip \uXXXX (loop adds 1)
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseHex4 parses exactly 4 hex digits into a rune.
func parseHex4(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var r rune
	for _, c := range []byte(s) {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

// DeduplicateSlice returns a unique, deduplicated slice of strings.
func DeduplicateSlice(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, val := range in {
		if !seen[val] {
			seen[val] = true
			out = append(out, val)
		}
	}
	return out
}

// CountUniqueDNSxHosts reads a DNSx JSONL output file and counts the unique hosts resolved
func CountUniqueDNSxHosts(jsonPath string) (int, error) {
	file, err := os.Open(jsonPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	type dnsxRecord struct {
		Host string `json:"host"`
	}

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Host != "" {
			seen[strings.ToLower(strings.TrimSpace(rec.Host))] = true
		}
	}
	return len(seen), scanner.Err()
}
