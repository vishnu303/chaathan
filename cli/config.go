package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/logger"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Chaathan configuration",
	Long:  `View, edit, or reset the Chaathan configuration file.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Run:   runConfigShow,
}

var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Open configuration file in editor",
	Run:   runConfigEdit,
}

var configResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset configuration to defaults",
	Run:   runConfigReset,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show configuration file path",
	Run:   runConfigPath,
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Long: `Set a configuration value. Examples:
  chaathan config set api_keys.github ghp_xxxxx
  chaathan config set general.verbose true
  chaathan config set notifications.discord_webhook https://discord.com/api/webhooks/xxx`,
	Args: cobra.ExactArgs(2),
	Run:  runConfigSet,
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configEditCmd)
	configCmd.AddCommand(configResetCmd)
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) {
	cfgPath := config.GetDefaultConfigPath()

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warning("No configuration file found. Creating default...")
			_, err = config.LoadOrCreate(cfgPath)
			if err != nil {
				logger.Error("Failed to create config: %v", err)
				return
			}
			data, _ = os.ReadFile(cfgPath)
		} else {
			logger.Error("Failed to read config: %v", err)
			return
		}
	}

	fmt.Println(string(data))
}

func runConfigEdit(cmd *cobra.Command, args []string) {
	cfgPath := config.GetDefaultConfigPath()

	// Ensure config exists
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		logger.Info("Creating default configuration...")
		if _, err := config.LoadOrCreate(cfgPath); err != nil {
			logger.Error("Failed to create config: %v", err)
			return
		}
	}

	// Determine editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		switch runtime.GOOS {
		case "windows":
			editor = "notepad"
		case "darwin":
			editor = "nano"
		default:
			editor = "vim"
		}
	}

	logger.Info("Opening config in %s...", editor)

	c := exec.Command(editor, cfgPath)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		logger.Error("Failed to open editor: %v", err)
		logger.Info("Config file location: %s", cfgPath)
	}
}

func runConfigReset(cmd *cobra.Command, args []string) {
	cfgPath := config.GetDefaultConfigPath()

	logger.Warning("This will reset your configuration to defaults.")
	logger.Warning("Your current config will be backed up.")

	// Backup existing config
	if _, err := os.Stat(cfgPath); err == nil {
		backupPath := cfgPath + ".backup"
		if err := os.Rename(cfgPath, backupPath); err != nil {
			logger.Error("Failed to backup config: %v", err)
			return
		}
		logger.Info("Backed up to: %s", backupPath)
	}

	// Create new default config
	cfg := config.DefaultConfig()
	if err := config.Save(cfg, cfgPath); err != nil {
		logger.Error("Failed to create config: %v", err)
		return
	}

	logger.Success("Configuration reset to defaults!")
	logger.Info("Config file: %s", cfgPath)
}

func runConfigPath(cmd *cobra.Command, args []string) {
	fmt.Println(config.GetDefaultConfigPath())
}

// ─────────────────────────────────────────────────────────────
// Config key registry (F17)
//
// Each entry maps a dot-separated key to a setter function.
// Adding a new key requires only adding one line here — the help
// text and validation are auto-generated from the map keys.
// ─────────────────────────────────────────────────────────────

type configSetter func(cfg *config.Config, value string)

var configKeys = map[string]configSetter{
	// API keys
	"api_keys.github":         func(c *config.Config, v string) { c.APIKeys.GitHub = v },
	"api_keys.shodan":         func(c *config.Config, v string) { c.APIKeys.Shodan = v },
	"api_keys.securitytrails": func(c *config.Config, v string) { c.APIKeys.SecurityTrails = v },
	"api_keys.virustotal":     func(c *config.Config, v string) { c.APIKeys.VirusTotal = v },
	"api_keys.chaos":          func(c *config.Config, v string) { c.APIKeys.Chaos = v },

	// General
	"general.verbose":    func(c *config.Config, v string) { c.General.Verbose = v == "true" },
	"general.mode":       func(c *config.Config, v string) { c.General.Mode = v },
	"general.output_dir": func(c *config.Config, v string) { c.General.OutputDir = v },

	// Notifications
	"notifications.discord_webhook": func(c *config.Config, v string) {
		c.Notifications.DiscordWebhook = v
		c.Notifications.Enabled = true
	},
	"notifications.slack_webhook": func(c *config.Config, v string) {
		c.Notifications.SlackWebhook = v
		c.Notifications.Enabled = true
	},
	"notifications.telegram_bot_token": func(c *config.Config, v string) { c.Notifications.TelegramBotToken = v },
	"notifications.telegram_chat_id":   func(c *config.Config, v string) { c.Notifications.TelegramChatID = v },
	"notifications.enabled":            func(c *config.Config, v string) { c.Notifications.Enabled = v == "true" },
	"notifications.step_complete":      func(c *config.Config, v string) { c.Notifications.StepComplete = v == "true" },
	"notifications.min_severity":       func(c *config.Config, v string) { c.Notifications.MinSeverity = v },
}

func runConfigSet(cmd *cobra.Command, args []string) {
	key := args[0]
	value := args[1]

	cfgPath := config.GetDefaultConfigPath()

	// Load or create config
	cfg, err := config.LoadOrCreate(cfgPath)
	if err != nil {
		logger.Error("Failed to load config: %v", err)
		return
	}

	// Look up setter in registry
	setter, ok := configKeys[key]
	if !ok {
		logger.Error("Unknown config key: %s", key)
		logger.Info("Available keys:")

		// Group keys by prefix for pretty display
		groups := map[string][]string{}
		for k := range configKeys {
			prefix := strings.SplitN(k, ".", 2)[0]
			groups[prefix] = append(groups[prefix], k)
		}
		for prefix, keys := range groups {
			logger.Info("  [%s]", prefix)
			for _, k := range keys {
				logger.Info("    %s", k)
			}
		}
		return
	}

	setter(cfg, value)

	// Save config
	if err := config.Save(cfg, cfgPath); err != nil {
		logger.Error("Failed to save config: %v", err)
		return
	}

	logger.Success("Set %s = %s", key, maskSecret(key, value))
}

func maskSecret(key, value string) string {
	// Mask sensitive values
	if len(value) > 8 && (strings.Contains(key, "token") || strings.Contains(key, "key") || strings.Contains(key, "secret") || strings.Contains(key, "webhook")) {
		return value[:4] + "****" + value[len(value)-4:]
	}
	return value
}
