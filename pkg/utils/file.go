package utils

import (
	"bufio"
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
