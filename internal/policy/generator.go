package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	// Note: we deliberately do NOT mark any fields inside condition as
	// required. Gemini's responseSchema dialect has no way to say "this
	// object may be absent," so required-string fields get emitted with the
	// literal value "null" when the model has nothing to say — which then
	// spills into hallucinated garbage in adjacent fields. Making every
	// sub-field optional lets the model emit an empty condition or omit it
	// entirely; the post-parse normalize() in types.go drops either shape.
	conditionSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title":       map[string]any{"type": "string"},
			"description": map[string]any{"type": "string"},
			"expression":  map[string]any{"type": "string"},
		},
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
					"resource_type": map[string]any{
						"type": "string",
						"enum": []string{
							"bigquery_dataset",
							"bigquery_table",
							"storage_bucket",
							"pubsub_topic",
							"secret_manager_secret",
							"cloud_run_service",
						},
					},
					"project":  map[string]any{"type": "string"},
					"location": map[string]any{"type": "string"},
					"parent":   map[string]any{"type": "string"},
				},
				"required": []string{"type", "id"},
			},
			// maxItems caps on the advisory arrays below are a defense
			// against a Gemini failure mode: with constrained decoding, the
			// model sometimes falls into a repetition loop and emits the
			// literal string "null" hundreds of times into whichever free-form
			// array appears next in the schema. That blows past MaxTokens
			// before the JSON closes, and the whole response parse fails. A
			// sensible cap (arrays this long are never useful anyway) makes
			// the failure mode impossible to reach.
			"bindings":  map[string]any{"type": "array", "items": bindingSchema},
			"rationale": map[string]any{"type": "array", "items": rationaleItemSchema},
			// maxItems on the two free-form string arrays below is a
			// defense against a Gemini failure mode: with constrained
			// decoding, the model occasionally falls into a repetition loop
			// and fills whichever free-form array comes next in the schema
			// with the literal string "null" hundreds of times, blowing
			// past MaxTokens before the JSON closes. Caps on the nested
			// object arrays above are rejected as "too many states for
			// serving", but caps on plain string arrays are accepted — so
			// we cap exactly where the loop happens.
			"warnings":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 10},
			"alternatives":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 5},
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

	// Back-fill Scope.Project for resource-scoped bindings when the model
	// forgot to include it. Most `google_*_iam_member` resources (BigQuery,
	// Pub/Sub, Secret Manager, Cloud Run) have a required `project` field, so
	// an empty string here renders invalid HCL. If the caller passed a
	// project via --context, reuse it here instead of erroring.
	if rec.Scope.Type == "resource" && rec.Scope.Project == "" {
		if p := projectFromHints(opts.ContextHints); p != "" {
			rec.Scope.Project = p
		}
	}

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

// projectFromHints scans ContextHints for a "project: <id>" or "project=<id>"
// pair (case-insensitive on the key) and returns the first value found. We
// accept a few shapes because the CLI flag is free-form; any hint that
// doesn't start with a recognizable "project" key is ignored.
func projectFromHints(hints []string) string {
	for _, h := range hints {
		for _, sep := range []string{":", "="} {
			if i := strings.Index(h, sep); i > 0 {
				key := strings.TrimSpace(strings.ToLower(h[:i]))
				if key == "project" || key == "project_id" || key == "project-id" {
					return strings.TrimSpace(h[i+1:])
				}
			}
		}
	}
	return ""
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
