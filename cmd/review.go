package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/fathomforge/iam-assist/internal/policy"
	"github.com/fathomforge/iam-assist/internal/terraform"
)

// maxPolicyBytes caps how much JSON we will buffer when loading a policy
// recommendation from stdin or a file. 8 MiB is generous for the largest
// realistic recommendation while preventing memory-exhaustion DoS.
const maxPolicyBytes = 8 << 20 // 8 MiB

var reviewCmd = &cobra.Command{
	Use:   "review [file.json]",
	Short: "Interactively review and approve a generated IAM policy",
	Long: `Review loads a previously generated policy recommendation (JSON)
and walks you through an interactive approval flow.

Examples:
  iam-assist generate --json "read BigQuery" > policy.json
  iam-assist review policy.json
  iam-assist generate "deploy Cloud Run" | iam-assist review -`,
	Args: cobra.MaximumNArgs(1),
	RunE: runReview,
}

func init() {
	rootCmd.AddCommand(reviewCmd)
	reviewCmd.Flags().Bool("terraform", false, "output approved policy as Terraform HCL")
	reviewCmd.Flags().StringP("out", "o", "", "write approved output to file")
}

func runReview(cmd *cobra.Command, args []string) error {
	// 1. Load the recommendation.
	var data []byte
	var err error

	if len(args) == 0 || args[0] == "-" {
		data, err = readStdin()
	} else {
		data, err = readCappedFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var rec policy.PolicyRecommendation
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("parsing policy JSON: %w", err)
	}

	// 2. Display the policy.
	fmt.Print(policy.FormatTerminal(&rec))

	risk := policy.Assess(&rec)

	// 3. Interactive review.
	scanner := bufio.NewScanner(os.Stdin)

	if risk.Level == policy.RiskHigh {
		fmt.Printf("\n%s⚠ HIGH RISK POLICY — requires explicit confirmation%s\n", "\033[31m\033[1m", "\033[0m")
	}

	// Review each binding.
	approvedBindings := make([]policy.Binding, 0, len(rec.Bindings))
	for i, b := range rec.Bindings {
		// Sanitize everything that came from the JSON before writing to the
		// terminal — otherwise a malicious policy.json could inject ANSI
		// cursor-movement sequences to mask this prompt and trick the user
		// into approving something they aren't actually reading.
		fmt.Printf("\n[%d/%d] %s → %s\n",
			i+1, len(rec.Bindings), policy.SanitizeDisplay(b.Role), policy.SanitizeDisplay(membersStr(b.Members)))
		fmt.Print("  (a)pprove / (s)kip / (e)dit role / (q)uit? ")

		if !scanner.Scan() {
			return fmt.Errorf("input interrupted")
		}

		switch strings.TrimSpace(strings.ToLower(scanner.Text())) {
		case "a", "approve", "":
			approvedBindings = append(approvedBindings, b)
			fmt.Println("  ✅ Approved")
		case "s", "skip":
			fmt.Println("  ⏭ Skipped")
		case "e", "edit":
			fmt.Print("  New role (e.g. roles/bigquery.dataViewer): ")
			if scanner.Scan() {
				newRole := strings.TrimSpace(scanner.Text())
				if newRole != "" {
					if !policy.IsValidRoleRef(newRole) {
						fmt.Printf("  ❌ %q is not a valid GCP role format (expected roles/<service>.<name> or projects/.../roles/...). Keeping original.\n", policy.SanitizeDisplay(newRole))
					} else {
						if policy.LookupRole(newRole) == nil {
							fmt.Printf("  ⚠  %q is not in the built-in role database (may be a new or custom role).\n", newRole)
						}
						b.Role = newRole
					}
				}
			}
			approvedBindings = append(approvedBindings, b)
			fmt.Printf("  ✅ Approved with role: %s\n", policy.SanitizeDisplay(b.Role))
		case "q", "quit":
			fmt.Println("  Aborted.")
			return nil
		default:
			fmt.Println("  Unknown option, skipping.")
		}
	}

	if len(approvedBindings) == 0 {
		fmt.Println("\nNo bindings approved.")
		return nil
	}

	rec.Bindings = approvedBindings

	// 4. Optional refinement.
	fmt.Print("\nRun least-privilege refinement on approved bindings? (y/N) ")
	if scanner.Scan() && strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
		p, err := initProvider()
		if err != nil {
			return fmt.Errorf("provider init: %w", err)
		}
		gen := policy.NewGenerator(p)
		fmt.Fprintln(os.Stderr, "🔒 Refining...")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		refined, err := gen.Generate(ctx, rec.Request, policy.GenerateOptions{Refine: true})
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ Refinement failed: %v (using original)\n", err)
		} else {
			rec = *refined
		}
	}

	// 5. Output.
	outputTF, _ := cmd.Flags().GetBool("terraform")
	outFile, _ := cmd.Flags().GetString("out")

	var output string
	if outputTF {
		output, err = terraform.Render(&rec)
		if err != nil {
			return fmt.Errorf("terraform render: %w", err)
		}
	} else {
		output, err = rec.ToJSON()
		if err != nil {
			return fmt.Errorf("JSON serialization: %w", err)
		}
	}

	if outFile != "" {
		// 0600: the approved policy can contain member emails, internal
		// project IDs, and other information the user hasn't chosen to share
		// with other local accounts. Match init.go's config perms.
		if err := os.WriteFile(outFile, []byte(output), 0600); err != nil {
			return fmt.Errorf("writing %s: %w", outFile, err)
		}
		fmt.Fprintf(os.Stderr, "\n✅ Approved policy written to %s\n", outFile)
	} else {
		fmt.Printf("\n%s\n", output)
	}

	return nil
}

func membersStr(members []policy.Member) string {
	parts := make([]string, len(members))
	for i, m := range members {
		parts[i] = m.IAMIdentity()
	}
	return strings.Join(parts, ", ")
}

func readStdin() ([]byte, error) {
	// Read one byte past the cap so we can detect an oversized input rather
	// than silently truncating what might be valid JSON.
	buf, err := io.ReadAll(io.LimitReader(os.Stdin, maxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxPolicyBytes {
		return nil, fmt.Errorf("stdin input exceeds %d bytes", maxPolicyBytes)
	}
	return buf, nil
}

// readCappedFile reads path with a size ceiling so that piping an enormous
// file into `iam-assist review some.json` cannot exhaust memory.
func readCappedFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path is user-provided by design (CLI arg)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxPolicyBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxPolicyBytes)
	}
	return buf, nil
}
