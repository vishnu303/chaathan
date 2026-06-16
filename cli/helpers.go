package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

// parseScanIDArg parses the scan ID string, logs any error, and returns the parsed ID and success status.
func parseScanIDArg(arg string) (int64, bool) {
	id, err := utils.ParseScanID(arg)
	if err != nil {
		logger.Error("%v", err)
		return 0, false
	}
	return id, true
}

// parseDaysArg parses the days string, logs any error, and returns the parsed days and success status.
func parseDaysArg(arg string) (int, bool) {
	days, err := utils.ParseDays(arg)
	if err != nil {
		logger.Error("%v", err)
		return 0, false
	}
	return days, true
}

// writeJSONOrPrint writes indented JSON to a file if filePath is specified, otherwise prints to stdout.
func writeJSONOrPrint(v interface{}, filePath string) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal JSON: %v", err)
		return
	}
	if filePath != "" {
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			logger.Error("Failed to write JSON output: %v", err)
			return
		}
		logger.Success("Results saved to: %s", filePath)
		return
	}
	fmt.Println(string(data))
}

// overrideConfigOverrides applies CLI-specific overrides to the global configuration.
func overrideConfigOverrides(proxy string, rateLimit int) {
	if Cfg == nil {
		return
	}
	if proxy != "" {
		Cfg.General.Proxy = proxy
	}
	if rateLimit > 0 {
		Cfg.RateLimits.GlobalRPS = rateLimit
	}
}

// resolvePath retrieves the resolved path from flag value or config fallback.
func resolvePath(flagVal, configVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if Cfg != nil {
		return configVal
	}
	return ""
}
