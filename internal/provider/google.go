package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	googleDefaultModel = "gemini-2.5-flash"
	googleAPIURL       = "https://generativelanguage.googleapis.com/v1beta/models"
)

type googleProvider struct {
	apiKey string
	model  string
	client *http.Client
}

func NewGoogle(apiKey, model string) (Provider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("google API key required (set GOOGLE_API_KEY or --api-key)")
	}
	if model == "" {
		model = googleDefaultModel
	}
	return &googleProvider{apiKey: apiKey, model: model, client: &http.Client{}}, nil
}

func (g *googleProvider) Name() string { return "google" }

func (g *googleProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Build Gemini-format contents.
	var systemInstruction string
	contents := make([]map[string]any, 0, len(req.Messages))

	for _, m := range req.Messages {
		if m.Role == "system" {
			systemInstruction = m.Content
			continue
		}
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		contents = append(contents, map[string]any{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		})
	}

	generationConfig := map[string]any{
		"temperature":     req.Temperature,
		"maxOutputTokens": req.MaxTokens,
	}
	// Gemini supports constrained JSON output via responseSchema +
	// responseMimeType. When the caller provides a schema we turn this on
	// so the model literally cannot emit anything but well-formed JSON
	// matching the contract — this eliminates the "model returned a
	// string instead of an array" class of refinement-pass failures.
	if req.ResponseSchema != nil {
		generationConfig["responseMimeType"] = "application/json"
		generationConfig["responseSchema"] = req.ResponseSchema
	}
	body := map[string]any{
		"contents":         contents,
		"generationConfig": generationConfig,
	}
	if systemInstruction != "" {
		body["systemInstruction"] = map[string]any{
			"parts": []map[string]string{{"text": systemInstruction}},
		}
	}

	payload, _ := json.Marshal(body)

	// Pass the API key in a header rather than the URL query string so it
	// never appears in *url.Error messages, transport logs, or proxy access
	// logs. The Gemini API supports both forms.
	url := fmt.Sprintf("%s/%s:generateContent", googleAPIURL, g.model)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", g.apiKey)

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("google request failed: %w", redactKey(err, g.apiKey))
	}
	defer resp.Body.Close()

	respBody, _ := readCappedBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google API error (%d): %s", resp.StatusCode, truncateForError(string(respBody)))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	text := ""
	if len(result.Candidates) > 0 {
		for _, p := range result.Candidates[0].Content.Parts {
			text += p.Text
		}
	}

	return &CompletionResponse{
		Content:      text,
		Model:        g.model,
		InputTokens:  result.UsageMetadata.PromptTokenCount,
		OutputTokens: result.UsageMetadata.CandidatesTokenCount,
	}, nil
}
