package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/fathomforge/iam-assist/internal/policy"
)

var validateCmd = &cobra.Command{
	Use:   "validate [policy.json]",
	Short: "Validate a generated policy against known GCP roles and least-privilege rules",
	Long: `Validate checks a policy recommendation (JSON) against the built-in
GCP role database and reports potential over-privilege issues.

This runs entirely offline — no AI calls needed.

Examples:
  iam-assist generate --json "admin access" | iam-assist validate -
  iam-assist validate policy.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	var data []byte
	var err error

	if len(args) == 0 || args[0] == "-" {
		data, err = readStdin()
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var rec policy.PolicyRecommendation
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("parsing policy JSON: %w", err)
	}

	// Run risk assessment.
	risk := policy.Assess(&rec)

	// Run role validation.
	roleWarnings := policy.ValidateBindings(rec.Bindings)

	// Display results.
	fmt.Printf("\n\033[1m\033[36m Validation Report\033[0m\n")
	fmt.Println("────────────────────────────────────────────────────────────")

	// Risk.
	riskColor := "\033[32m"
	switch risk.Level {
	case policy.RiskMedium:
		riskColor = "\033[33m"
	case policy.RiskHigh:
		riskColor = "\033[31m"
	}
	fmt.Printf("\n\033[1mRisk Level:\033[0m %s%s\033[0m\n", riskColor, risk.Level)
	for _, r := range risk.Reasons {
		fmt.Printf("  • %s\n", r)
	}

	// Binding details.
	fmt.Printf("\n\033[1mBindings (%d):\033[0m\n", len(rec.Bindings))
	for _, b := range rec.Bindings {
		info := policy.LookupRole(b.Role)
		if info != nil {
			fmt.Printf("  ✓ %s — %s (%d permissions)\n", b.Role, info.Title, info.PermissionCount)
		} else {
			fmt.Printf("  ? %s — not in known role database\n", b.Role)
		}
	}

	// Warnings the AI emitted alongside the policy itself. These are often
	// the most useful red flags (e.g. "external identities are being granted
	// access to billing data") and were previously silently dropped here.
	if len(rec.Warnings) > 0 {
		fmt.Printf("\n\033[1m\033[33m⚠ Policy Warnings:\033[0m\n")
		for _, w := range rec.Warnings {
			fmt.Printf("  \033[33m• %s\033[0m\n", w)
		}
	}

	// Warnings from offline role validation against the built-in DB.
	if len(roleWarnings) > 0 {
		fmt.Printf("\n\033[1m\033[33m⚠ Least-Privilege Warnings:\033[0m\n")
		for _, w := range roleWarnings {
			fmt.Printf("  \033[33m• %s\033[0m\n", w)
		}
	}

	// Alternatives the AI suggested. Surfacing these is cheap and helps
	// users tighten the policy before applying.
	if len(rec.Alternatives) > 0 {
		fmt.Printf("\n\033[1m\033[36mAlternatives to consider:\033[0m\n")
		for _, a := range rec.Alternatives {
			fmt.Printf("  \033[2m• %s\033[0m\n", a)
		}
	}

	// Overall verdict.
	fmt.Println()
	if risk.Level == policy.RiskHigh || len(roleWarnings) > 2 {
		fmt.Println("\033[31m✗ FAIL — policy needs tightening. Run with --refine or use 'iam-assist review'.\033[0m")
		os.Exit(1)
	} else if risk.Level == policy.RiskMedium || len(roleWarnings) > 0 {
		fmt.Println("\033[33m⚠ WARN — policy has potential over-privilege. Consider refinement.\033[0m")
	} else {
		fmt.Println("\033[32m✓ PASS — policy follows least-privilege principles.\033[0m")
	}

	return nil
}
