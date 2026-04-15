package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	anthropicDefaultModel = "claude-sonnet-4-20250514"
	anthropicAPIURL       = "https://api.anthropic.com/v1/messages"
)

type anthropicProvider struct {
	apiKey string
	model  string
	client *http.Client
}

func NewAnthropic(apiKey, model string) (Provider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("anthropic API key required (set ANTHROPIC_API_KEY or --api-key)")
	}
	if model == "" {
		model = anthropicDefaultModel
	}
	return &anthropicProvider{apiKey: apiKey, model: model, client: &http.Client{}}, nil
}

func (a *anthropicProvider) Name() string { return "anthropic" }

func (a *anthropicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Separate system message from conversation messages.
	var system string
	msgs := make([]map[string]string, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	body := map[string]any{
		"model":       a.model,
		"max_tokens":  maxTokens,
		"messages":    msgs,
		"temperature": req.Temperature,
	}
	if system != "" {
		body["system"] = system
	}

	payload, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	text := ""
	for _, c := range result.Content {
		text += c.Text
	}

	return &CompletionResponse{
		Content:      text,
		Model:        result.Model,
		InputTokens:  result.Usage.InputTokens,
		OutputTokens: result.Usage.OutputTokens,
	}, nil
}
