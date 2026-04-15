package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/fathomforge/iam-assist/internal/prompt"
	"github.com/fathomforge/iam-assist/internal/provider"
)

// ErrRefinementFailed is returned (wrapped) by Generate when the refinement
// pass could not be completed. The unrefined first-pass recommendation is
// still returned alongside the error so callers can fall back to it.
var ErrRefinementFailed = errors.New("refinement pass failed")

// GenerateOptions configures the generation pipeline.
type GenerateOptions struct {
	// Refine enables a second-pass least-privilege refinement.
	Refine bool

	// ContextHints provides additional context (project IDs, team names, etc).
	ContextHints []string

	// Temperature for AI generation (lower = more deterministic).
	Temperature float64
}

// Generator orchestrates the NL → IAM policy pipeline.
type Generator struct {
	provider provider.Provider
}

// NewGenerator creates a Generator with the given AI provider.
func NewGenerator(p provider.Provider) *Generator {
	return &Generator{provider: p}
}

// policyRecommendationSchema returns a JSON-Schema-subset description of the
// PolicyRecommendation shape in the dialect Gemini's responseSchema accepts.
// Gemini supports a restricted subset — notably no oneOf/anyOf — so we pin
// rationale to the canonical structured array here. The tolerant
// RationaleField parser remains as a safety net for providers that don't
// enforce the schema (OpenAI/Anthropic) and for the refinement pass.
func policyRecommendationSchema() map[string]any {
	memberSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"type":    map[string]any{"type": "string", "enum": []string{"user", "group", "serviceAccount", "domain"}},
			"email":   map[string]any{"type": "string"},
			"display": map[string]any{"type": "string"},
		},
		"required": []string{"type", "email"},
	}
	conditionSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title":       map[string]any{"type": "string"},
			"description": map[string]any{"type": "string"},
			"expression":  map[string]any{"type": "string"},
		},
		"required": []string{"title", "expression"},
	}
	bindingSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"role":      map[string]any{"type": "string"},
			"members":   map[string]any{"type": "array", "items": memberSchema},
			"condition": conditionSchema,
		},
		"required": []string{"role", "members"},
	}
	rationaleItemSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"permission": map[string]any{"type": "string"},
			"reason":     map[string]any{"type": "string"},
		},
		"required": []string{"permission", "reason"},
	}
	customRoleSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id":          map[string]any{"type": "string"},
			"title":       map[string]any{"type": "string"},
			"description": map[string]any{"type": "string"},
			"permissions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"stage":       map[string]any{"type": "string"},
		},
		"required": []string{"id", "title", "permissions"},
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"scope": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"type":    map[string]any{"type": "string", "enum": []string{"project", "folder", "organization", "resource"}},
					"id":      map[string]any{"type": "string"},
					"display": map[string]any{"type": "string"},
				},
				"required": []string{"type", "id"},
			},
			"bindings":         map[string]any{"type": "array", "items": bindingSchema},
			"rationale":        map[string]any{"type": "array", "items": rationaleItemSchema},
			"warnings":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"alternatives":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"uses_custom_role": map[string]any{"type": "boolean"},
			"custom_role":      customRoleSchema,
		},
		"required": []string{"scope", "bindings"},
	}
}

// Generate converts a natural language request into a PolicyRecommendation.
func (g *Generator) Generate(ctx context.Context, request string, opts GenerateOptions) (*PolicyRecommendation, error) {
	// 1. Build the initial prompt.
	promptMsgs := prompt.BuildGenerateMessages(request, opts.ContextHints...)

	providerMsgs := make([]provider.Message, len(promptMsgs))
	for i, m := range promptMsgs {
		providerMsgs[i] = provider.Message{Role: m.Role, Content: m.Content}
	}

	temp := opts.Temperature
	if temp == 0 {
		temp = 0.1 // Low temperature for deterministic policy output.
	}

	// 2. Call the AI provider.
	resp, err := g.provider.Complete(ctx, provider.CompletionRequest{
		Messages:       providerMsgs,
		Temperature:    temp,
		MaxTokens:      8192,
		ResponseSchema: policyRecommendationSchema(),
	})
	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %w", err)
	}

	// 3. Parse the response.
	rec, err := ParseRecommendation(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}
	rec.Request = request

	// 4. Optional refinement pass.
	if opts.Refine {
		refined, refineErr := g.refine(ctx, rec, temp)
		if refineErr != nil {
			// Return the unrefined recommendation with a sentinel error
			// the CLI can detect via errors.Is. The recommendation is still
			// usable; the caller decides how to surface the failure.
			return rec, fmt.Errorf("%w: %v", ErrRefinementFailed, refineErr)
		}
		rec = refined
	}

	return rec, nil
}

// refine runs a second AI pass to tighten the policy.
func (g *Generator) refine(ctx context.Context, rec *PolicyRecommendation, temperature float64) (*PolicyRecommendation, error) {
	policyJSON, err := rec.ToJSON()
	if err != nil {
		return rec, fmt.Errorf("serializing for refinement: %w", err)
	}

	refineMsgs := prompt.BuildRefineMessages(rec.Request, policyJSON)

	providerMsgs := make([]provider.Message, len(refineMsgs))
	for i, m := range refineMsgs {
		providerMsgs[i] = provider.Message{Role: m.Role, Content: m.Content}
	}

	// Refined output is strictly larger than first-pass output (it includes
	// the original plus added rationale, warnings, and possibly a custom
	// role with a permissions list), so give it more headroom than the
	// 4096-token first pass.
	resp, err := g.provider.Complete(ctx, provider.CompletionRequest{
		Messages:       providerMsgs,
		Temperature:    temperature,
		MaxTokens:      16384,
		ResponseSchema: policyRecommendationSchema(),
	})
	if err != nil {
		return rec, fmt.Errorf("refinement call failed: %w", err)
	}

	refined, err := ParseRecommendation(resp.Content)
	if err != nil {
		return rec, fmt.Errorf("parsing refinement response: %w", err)
	}
	refined.Request = rec.Request

	return refined, nil
}
