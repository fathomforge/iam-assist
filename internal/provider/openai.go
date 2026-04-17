package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	openaiDefaultModel = "gpt-4o"
	openaiAPIURL       = "https://api.openai.com/v1/chat/completions"
)

type openaiProvider struct {
	apiKey string
	model  string
	client *http.Client
}

func NewOpenAI(apiKey, model string) (Provider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("openai API key required (set OPENAI_API_KEY or --api-key)")
	}
	if model == "" {
		model = openaiDefaultModel
	}
	return &openaiProvider{apiKey: apiKey, model: model, client: &http.Client{}}, nil
}

func (o *openaiProvider) Name() string { return "openai" }

func (o *openaiProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	msgs := make([]map[string]string, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	body := map[string]any{
		"model":       o.model,
		"max_tokens":  maxTokens,
		"messages":    msgs,
		"temperature": req.Temperature,
	}

	payload, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", openaiAPIURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai request failed: %w", redactKey(err, o.apiKey))
	}
	defer resp.Body.Close()

	respBody, _ := readCappedBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai API error (%d): %s", resp.StatusCode, truncateForError(string(respBody)))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	text := ""
	if len(result.Choices) > 0 {
		text = result.Choices[0].Message.Content
	}

	return &CompletionResponse{
		Content:      text,
		Model:        result.Model,
		InputTokens:  result.Usage.PromptTokens,
		OutputTokens: result.Usage.CompletionTokens,
	}, nil
}
