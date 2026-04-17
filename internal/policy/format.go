package policy

import (
	"fmt"
	"strings"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// sd is a shorthand for SanitizeDisplay applied to a single field. Every
// string that originated from an LLM response or a JSON file — i.e. every
// field an attacker could populate — is routed through sd before being
// written into the terminal output. Keeping the alias short keeps the format
// code readable.
var sd = SanitizeDisplay

// FormatTerminal produces a human-readable terminal display of a PolicyRecommendation.
func FormatTerminal(rec *PolicyRecommendation) string {
	var b strings.Builder

	risk := Assess(rec)

	// Header.
	b.WriteString(fmt.Sprintf("\n%s%s IAM Policy Recommendation%s\n", colorBold, colorCyan, colorReset))
	b.WriteString(strings.Repeat("─", 60) + "\n\n")

	// Request.
	b.WriteString(fmt.Sprintf("%sRequest:%s %s\n", colorBold, colorReset, sd(rec.Request)))
	b.WriteString(fmt.Sprintf("%sScope:%s   %s\n", colorBold, colorReset, sd(rec.Scope.String())))

	// Risk.
	riskColor := colorGreen
	switch risk.Level {
	case RiskMedium:
		riskColor = colorYellow
	case RiskHigh:
		riskColor = colorRed
	}
	b.WriteString(fmt.Sprintf("%sRisk:%s    %s%s%s\n", colorBold, colorReset, riskColor, risk.Level, colorReset))
	for _, r := range risk.Reasons {
		b.WriteString(fmt.Sprintf("          %s• %s%s\n", colorDim, sd(r), colorReset))
	}
	b.WriteString("\n")

	// Bindings.
	b.WriteString(fmt.Sprintf("%s%sBindings:%s\n", colorBold, colorBlue, colorReset))
	for i, bind := range rec.Bindings {
		b.WriteString(fmt.Sprintf("  %d. %s%s%s\n", i+1, colorGreen, sd(bind.Role), colorReset))
		for _, m := range bind.Members {
			b.WriteString(fmt.Sprintf("     → %s\n", sd(m.IAMIdentity())))
		}
		if bind.Condition != nil {
			b.WriteString(fmt.Sprintf("     %sif%s %s\n", colorYellow, colorReset, sd(bind.Condition.Expression)))
		}
	}
	b.WriteString("\n")

	// Rationale — accept either the structured list or a free-form string.
	if len(rec.Rationale.Items) > 0 {
		b.WriteString(fmt.Sprintf("%s%sRationale:%s\n", colorBold, colorBlue, colorReset))
		for _, r := range rec.Rationale.Items {
			b.WriteString(fmt.Sprintf("  • %s%s%s: %s\n", colorCyan, sd(r.Permission), colorReset, sd(r.Reason)))
		}
		b.WriteString("\n")
	} else if rec.Rationale.Text != "" {
		b.WriteString(fmt.Sprintf("%s%sRationale:%s\n", colorBold, colorBlue, colorReset))
		b.WriteString(fmt.Sprintf("  %s\n\n", sd(rec.Rationale.Text)))
	}

	// Warnings.
	if len(rec.Warnings) > 0 {
		b.WriteString(fmt.Sprintf("%s%s⚠ Warnings:%s\n", colorBold, colorYellow, colorReset))
		for _, w := range rec.Warnings {
			b.WriteString(fmt.Sprintf("  %s• %s%s\n", colorYellow, sd(w), colorReset))
		}
		b.WriteString("\n")
	}

	// Alternatives.
	if len(rec.Alternatives) > 0 {
		b.WriteString(fmt.Sprintf("%sAlternatives to consider:%s\n", colorDim, colorReset))
		for _, a := range rec.Alternatives {
			b.WriteString(fmt.Sprintf("  %s• %s%s\n", colorDim, sd(a), colorReset))
		}
		b.WriteString("\n")
	}

	// Custom role.
	if rec.UsesCustomRole && rec.CustomRole != nil {
		b.WriteString(fmt.Sprintf("%s%sCustom Role:%s %s\n", colorBold, colorBlue, colorReset, sd(rec.CustomRole.Title)))
		b.WriteString(fmt.Sprintf("  ID: %s\n", sd(rec.CustomRole.ID)))
		b.WriteString("  Permissions:\n")
		for _, p := range rec.CustomRole.Permissions {
			b.WriteString(fmt.Sprintf("    • %s\n", sd(p)))
		}
		b.WriteString("\n")
	}

	return b.String()
}
