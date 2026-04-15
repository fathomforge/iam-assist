package provider

import (
	"context"
	"fmt"
)

// Message represents a chat message for the AI provider.
type Message struct {
	Role    string `json:"role"`    // "system", "user", "assistant"
	Content string `json:"content"`
}

// CompletionRequest holds the parameters for an AI completion call.
type CompletionRequest struct {
	Messages    []Message
	Temperature float64
	MaxTokens   int

	// ResponseSchema, if set, asks the provider to constrain the response
	// to a JSON document matching this schema. Providers that don't support
	// structured output silently ignore it. The value should be a Go map or
	// struct that JSON-marshals into the provider's expected schema dialect
	// (a subset of JSON Schema in practice).
	ResponseSchema any
}

// CompletionResponse holds the AI provider's response.
type CompletionResponse struct {
	Content      string
	Model        string
	InputTokens  int
	OutputTokens int
}

// Provider is the interface every AI backend must implement.
type Provider interface {
	// Name returns the provider identifier (e.g. "anthropic").
	Name() string

	// Complete sends a completion request and returns the response.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}

// Registry maps provider names to constructor functions.
var registry = map[string]func(apiKey, model string) (Provider, error){}

// Register adds a provider constructor to the registry.
func Register(name string, constructor func(apiKey, model string) (Provider, error)) {
	registry[name] = constructor
}

// New creates a provider instance by name.
func New(name, apiKey, model string) (Provider, error) {
	constructor, ok := registry[name]
	if !ok {
		available := make([]string, 0, len(registry))
		for k := range registry {
			available = append(available, k)
		}
		return nil, fmt.Errorf("unknown provider %q (available: %v)", name, available)
	}
	return constructor(apiKey, model)
}

func init() {
	Register("anthropic", NewAnthropic)
	Register("openai", NewOpenAI)
	Register("google", NewGoogle)
}
