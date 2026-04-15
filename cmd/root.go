package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "iam-assist",
	Short: "AI-powered least-privilege GCP IAM policy generator",
	Long: `iam-assist converts natural language access requests into
least-privilege GCP IAM policies with optional Terraform output.

Examples:
  iam-assist generate "Let the data team read BigQuery datasets in project analytics-prod"
  iam-assist generate --refine "Give CI/CD pipeline access to deploy Cloud Run services"
  iam-assist generate --terraform --out policy.tf "Storage admin for the ETL service account"`,
	// Version is populated via SetVersion() from main. Cobra auto-adds --version
	// and -v as soon as this field is non-empty.
	Version: "dev",
	// Don't dump --help after a runtime error. Usage output only makes sense
	// for actual flag/arg parsing failures, not "API key missing" or
	// "generation timed out" — those already have their own messages.
	SilenceUsage: true,
}

// SetVersion wires the build-time version into the root command so that
// `iam-assist --version` prints it. Called from main() after ldflags inject
// the value into main.version.
func SetVersion(v string) {
	if v != "" {
		rootCmd.Version = v
	}
	rootCmd.SetVersionTemplate("iam-assist {{.Version}}\n")
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default $HOME/.iam-assist.yaml)")
	rootCmd.PersistentFlags().String("provider", "anthropic", "AI provider: anthropic, openai, google")
	rootCmd.PersistentFlags().String("model", "", "model override (default per provider)")
	rootCmd.PersistentFlags().String("api-key", "", "API key (overrides env var)")

	viper.BindPFlag("provider", rootCmd.PersistentFlags().Lookup("provider"))
	viper.BindPFlag("model", rootCmd.PersistentFlags().Lookup("model"))
	viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		viper.AddConfigPath(filepath.Join(home))
		viper.AddConfigPath(".")
		viper.SetConfigName(".iam-assist")
		viper.SetConfigType("yaml")
	}

	// Environment variable bindings
	viper.SetEnvPrefix("IAM_ASSIST")
	viper.AutomaticEnv()

	// Map provider-specific env vars as fallbacks
	viper.BindEnv("anthropic_api_key", "ANTHROPIC_API_KEY")
	viper.BindEnv("openai_api_key", "OPENAI_API_KEY")
	viper.BindEnv("google_api_key", "GOOGLE_API_KEY")

	viper.ReadInConfig() // silently ignore if missing
}
