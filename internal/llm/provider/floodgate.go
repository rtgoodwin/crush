package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/llm/tools"
	"github.com/charmbracelet/crush/internal/message"
)

// FloodgateClient represents a client for Apple Floodgate API
type FloodgateClient struct {
	providerOptions providerClientOptions
	httpClient      *http.Client
	auth            *FloodgateAuth
	baseURL         string
	vertexBaseURL   string
}

// FloodgateAuth handles authentication for Floodgate
type FloodgateAuth struct {
	token      string
	expiryTime time.Time
	clientID   string
	mutex      sync.RWMutex
}

// Floodgate request/response types for OpenAI-compatible endpoint
type FloodgateMessage struct {
	Role       string              `json:"role"`
	Content    string              `json:"content"`
	ToolCalls  []FloodgateToolCall `json:"tool_calls,omitempty"`
	ToolCallID string              `json:"tool_call_id,omitempty"`
}

type FloodgateToolCall struct {
	ID       string                `json:"id"`
	Type     string                `json:"type"`
	Function FloodgateFunctionCall `json:"function"`
}

type FloodgateFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type FloodgateTool struct {
	Type     string               `json:"type"`
	Function FloodgateFunctionDef `json:"function"`
}

type FloodgateFunctionDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type FloodgateChatRequest struct {
	Model       string             `json:"model"`
	Messages    []FloodgateMessage `json:"messages"`
	Tools       []FloodgateTool    `json:"tools,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
	Temperature float64            `json:"temperature,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
}

type FloodgateChatResponse struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []FloodgateChoice `json:"choices"`
	Usage   FloodgateUsage    `json:"usage"`
}

type FloodgateChoice struct {
	Index        int              `json:"index"`
	Message      FloodgateMessage `json:"message"`
	FinishReason string           `json:"finish_reason"`
}

type FloodgateUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Vertex AI request/response types
type VertexContent struct {
	Role  string       `json:"role"`
	Parts []VertexPart `json:"parts"`
}

type VertexPart struct {
	Text string `json:"text"`
}

type VertexGenerationConfig struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
	TopK            *int     `json:"topK,omitempty"`
	TopP            *float64 `json:"topP,omitempty"`
}

type VertexSafetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

type VertexChatRequest struct {
	Contents         []VertexContent         `json:"contents"`
	GenerationConfig *VertexGenerationConfig `json:"generationConfig,omitempty"`
	SafetySettings   []VertexSafetySetting   `json:"safetySettings,omitempty"`
}

type VertexChatResponse struct {
	Candidates    []VertexCandidate `json:"candidates"`
	UsageMetadata *VertexUsage      `json:"usageMetadata,omitempty"`
}

type VertexCandidate struct {
	Content       VertexContent  `json:"content"`
	FinishReason  string         `json:"finishReason,omitempty"`
	SafetyRatings []SafetyRating `json:"safetyRatings,omitempty"`
}

type SafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

type VertexUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type FloodgateErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func newFloodgateClient(opts providerClientOptions) *FloodgateClient {
	auth := &FloodgateAuth{
		clientID: "hvys3fcwcteqrvw3qzkvtk86viuoqv",
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		// No timeout to allow long responses
	}

	return &FloodgateClient{
		providerOptions: opts,
		httpClient:      httpClient,
		auth:            auth,
		baseURL:         "https://floodgate.g.apple.com/api/openai/v1",
		vertexBaseURL:   "https://floodgate.g.apple.com/api/gemini/v1/publishers/google/models",
	}
}

// Authentication methods
func (a *FloodgateAuth) GetToken() (string, error) {
	a.mutex.RLock()
	if a.token != "" && time.Now().Before(a.expiryTime) {
		defer a.mutex.RUnlock()
		return a.token, nil
	}
	a.mutex.RUnlock()

	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Double-check after acquiring write lock
	if a.token != "" && time.Now().Before(a.expiryTime) {
		return a.token, nil
	}

	token, err := a.fetchNewToken()
	if err != nil {
		return "", err
	}

	a.token = token
	a.expiryTime = time.Now().Add(8 * time.Hour)
	return token, nil
}

func (a *FloodgateAuth) InvalidateToken() {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.token = ""
	a.expiryTime = time.Time{}
}

func (a *FloodgateAuth) fetchNewToken() (string, error) {
	args := []string{
		"getToken",
		"-C", a.clientID,
		"--token-type=oauth",
		"--interactivity-type=none",
		"-E", "prod",
		"-G", "pkce",
		"-o", "openid,dsid,accountname,profile,groups",
	}

	cmd := exec.Command("/usr/local/bin/appleconnect", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr := string(exitError.Stderr)
			if strings.Contains(stderr, "not found") {
				return "", fmt.Errorf("appleconnect not found at /usr/local/bin/appleconnect - please install it")
			}
			if strings.Contains(stderr, "network") || strings.Contains(stderr, "connection") {
				return "", fmt.Errorf("network error - check Apple VPN connection: %s", stderr)
			}
			return "", fmt.Errorf("appleconnect failed: %s", stderr)
		}
		return "", fmt.Errorf("failed to execute appleconnect: %v", err)
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return "", fmt.Errorf("appleconnect returned empty output")
	}

	tokens := strings.Fields(outputStr)
	if len(tokens) == 0 {
		return "", fmt.Errorf("no token found in appleconnect output")
	}

	return tokens[len(tokens)-1], nil
}

// HTTP request methods
func (c *FloodgateClient) makeRequest(method, endpoint string, body interface{}, attempt int) (*http.Response, error) {
	if attempt > 2 {
		return nil, fmt.Errorf("max retry attempts exceeded")
	}

	token, err := c.auth.GetToken()
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	url := c.baseURL + endpoint
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "crush/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "no such host") {
			if attempt < 2 {
				delay := time.Duration((attempt+1)*1000) * time.Millisecond
				time.Sleep(delay)
				return c.makeRequest(method, endpoint, body, attempt+1)
			}
		}
		return nil, err
	}

	// Handle 401 (token expired)
	if resp.StatusCode == 401 && attempt == 0 {
		resp.Body.Close()
		c.auth.InvalidateToken()
		return c.makeRequest(method, endpoint, body, attempt+1)
	}

	// Handle rate limiting (429)
	if resp.StatusCode == 429 && attempt < 2 {
		resp.Body.Close()
		time.Sleep(1 * time.Second)
		return c.makeRequest(method, endpoint, body, attempt+1)
	}

	// Handle service unavailable (503)
	if resp.StatusCode == 503 && attempt < 2 {
		resp.Body.Close()
		delay := time.Duration((attempt+1)*(attempt+1)) * time.Second
		time.Sleep(delay)
		return c.makeRequest(method, endpoint, body, attempt+1)
	}

	return resp, nil
}

func (c *FloodgateClient) makeVertexRequest(method, endpoint string, body interface{}, attempt int) (*http.Response, error) {
	if attempt > 2 {
		return nil, fmt.Errorf("max retry attempts exceeded")
	}

	token, err := c.auth.GetToken()
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	url := c.vertexBaseURL + endpoint
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "crush/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "no such host") {
			if attempt < 2 {
				delay := time.Duration((attempt+1)*1000) * time.Millisecond
				time.Sleep(delay)
				return c.makeVertexRequest(method, endpoint, body, attempt+1)
			}
		}
		return nil, err
	}

	// Handle 401 (token expired)
	if resp.StatusCode == 401 && attempt == 0 {
		resp.Body.Close()
		c.auth.InvalidateToken()
		return c.makeVertexRequest(method, endpoint, body, attempt+1)
	}

	// Handle rate limiting and service errors
	if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < 2 {
		resp.Body.Close()
		delay := time.Duration((attempt+1)*1000) * time.Millisecond
		time.Sleep(delay)
		return c.makeVertexRequest(method, endpoint, body, attempt+1)
	}

	return resp, nil
}

// Model type detection
func (c *FloodgateClient) isVertexModel(modelID string) bool {
	return strings.HasPrefix(modelID, "gemini-")
}

// Message conversion methods
func (c *FloodgateClient) convertToFloodgateMessages(messages []message.Message) []FloodgateMessage {
	var floodgateMessages []FloodgateMessage

	for _, msg := range messages {
		floodgateMsg := FloodgateMessage{}

		switch msg.Role {
		case message.System:
			floodgateMsg.Role = "system"
		case message.User:
			floodgateMsg.Role = "user"
		case message.Assistant:
			floodgateMsg.Role = "assistant"
		case message.Tool:
			floodgateMsg.Role = "tool"
		}

		// Handle content parts
		var contentBuilder strings.Builder
		for _, part := range msg.Parts {
			switch p := part.(type) {
			case message.TextContent:
				contentBuilder.WriteString(p.Text)
			case message.ToolCall:
				// Convert tool call to Floodgate format
				floodgateMsg.ToolCalls = append(floodgateMsg.ToolCalls, FloodgateToolCall{
					ID:   p.ID,
					Type: "function",
					Function: FloodgateFunctionCall{
						Name:      p.Name,
						Arguments: p.Input,
					},
				})
			case message.ToolResult:
				floodgateMsg.ToolCallID = p.ToolCallID
				contentBuilder.WriteString(p.Content)
			}
		}

		floodgateMsg.Content = contentBuilder.String()
		floodgateMessages = append(floodgateMessages, floodgateMsg)
	}

	return floodgateMessages
}

func (c *FloodgateClient) convertToVertexContents(messages []message.Message) []VertexContent {
	var contents []VertexContent

	for _, msg := range messages {
		content := VertexContent{
			Parts: []VertexPart{},
		}

		// Convert role
		switch msg.Role {
		case message.User, message.System:
			content.Role = "user"
		case message.Assistant:
			content.Role = "model"
		default:
			content.Role = "user"
		}

		// Convert content parts
		var textBuilder strings.Builder
		for _, part := range msg.Parts {
			switch p := part.(type) {
			case message.TextContent:
				textBuilder.WriteString(p.Text)
			case message.ToolResult:
				textBuilder.WriteString(p.Content)
			case message.ToolCall:
				// For Vertex, represent tool calls as text (simplified)
				toolText := fmt.Sprintf("Tool call: %s(%s)", p.Name, p.Input)
				textBuilder.WriteString(toolText)
			}
		}

		if textBuilder.Len() > 0 {
			content.Parts = append(content.Parts, VertexPart{
				Text: textBuilder.String(),
			})
			contents = append(contents, content)
		}
	}

	return contents
}

func (c *FloodgateClient) convertTools(tools []tools.BaseTool) []FloodgateTool {
	var floodgateTools []FloodgateTool

	for _, tool := range tools {
		info := tool.Info()
		floodgateTool := FloodgateTool{
			Type: "function",
			Function: FloodgateFunctionDef{
				Name:        info.Name,
				Description: info.Description,
				Parameters:  info.Parameters,
			},
		}
		floodgateTools = append(floodgateTools, floodgateTool)
	}

	return floodgateTools
}

// Response conversion methods
func (c *FloodgateClient) convertFromFloodgateResponse(resp *FloodgateChatResponse) (*ProviderResponse, error) {
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := resp.Choices[0]
	providerResp := &ProviderResponse{
		Content: choice.Message.Content,
		Usage: TokenUsage{
			InputTokens:  int64(resp.Usage.PromptTokens),
			OutputTokens: int64(resp.Usage.CompletionTokens),
		},
		FinishReason: c.convertFinishReason(choice.FinishReason),
	}

	// Convert tool calls
	for _, toolCall := range choice.Message.ToolCalls {
		providerResp.ToolCalls = append(providerResp.ToolCalls, message.ToolCall{
			ID:    toolCall.ID,
			Name:  toolCall.Function.Name,
			Input: toolCall.Function.Arguments,
			Type:  toolCall.Type,
		})
	}

	return providerResp, nil
}

func (c *FloodgateClient) convertFromVertexResponse(resp *VertexChatResponse) (*ProviderResponse, error) {
	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no candidates in response")
	}

	candidate := resp.Candidates[0]
	providerResp := &ProviderResponse{
		Usage:        TokenUsage{},
		FinishReason: c.convertFinishReason(candidate.FinishReason),
	}

	// Convert usage metadata
	if resp.UsageMetadata != nil {
		providerResp.Usage = TokenUsage{
			InputTokens:  int64(resp.UsageMetadata.PromptTokenCount),
			OutputTokens: int64(resp.UsageMetadata.CandidatesTokenCount),
		}
	}

	// Extract text content
	var contentBuilder strings.Builder
	for _, part := range candidate.Content.Parts {
		contentBuilder.WriteString(part.Text)
	}
	providerResp.Content = contentBuilder.String()

	return providerResp, nil
}

func (c *FloodgateClient) convertFinishReason(reason string) message.FinishReason {
	switch reason {
	case "stop":
		return message.FinishReasonEndTurn
	case "length":
		return message.FinishReasonMaxTokens
	case "tool_calls":
		return message.FinishReasonToolUse
	case "content_filter":
		return message.FinishReasonPermissionDenied
	default:
		return message.FinishReasonEndTurn
	}
}

// Error handling
func (c *FloodgateClient) handleErrorResponse(resp *http.Response) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("HTTP %d: failed to read error response", resp.StatusCode)
	}

	var errorResp FloodgateErrorResponse
	if err := json.Unmarshal(bodyBytes, &errorResp); err != nil {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return fmt.Errorf("Floodgate API error (%d): %s", resp.StatusCode, errorResp.Error.Message)
}

// Main API methods
func (c *FloodgateClient) send(ctx context.Context, messages []message.Message, tools []tools.BaseTool) (*ProviderResponse, error) {
	model := c.Model()

	if c.isVertexModel(model.ID) {
		return c.sendVertexRequest(ctx, messages, tools, model)
	}
	return c.sendFloodgateRequest(ctx, messages, tools, model)
}

func (c *FloodgateClient) sendFloodgateRequest(ctx context.Context, messages []message.Message, tools []tools.BaseTool, model catwalk.Model) (*ProviderResponse, error) {
	req := FloodgateChatRequest{
		Model:       model.ID,
		Messages:    c.convertToFloodgateMessages(messages),
		Tools:       c.convertTools(tools),
		MaxTokens:   int(c.providerOptions.maxTokens),
		Temperature: 0.7, // Default temperature
	}

	resp, err := c.makeRequest("POST", "/chat/completions", req, 0)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, c.handleErrorResponse(resp)
	}

	var chatResp FloodgateChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return c.convertFromFloodgateResponse(&chatResp)
}

func (c *FloodgateClient) sendVertexRequest(ctx context.Context, messages []message.Message, tools []tools.BaseTool, model catwalk.Model) (*ProviderResponse, error) {
	req := VertexChatRequest{
		Contents: c.convertToVertexContents(messages),
		SafetySettings: []VertexSafetySetting{
			{Category: "HARM_CATEGORY_HARASSMENT", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
			{Category: "HARM_CATEGORY_HATE_SPEECH", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
			{Category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
			{Category: "HARM_CATEGORY_DANGEROUS_CONTENT", Threshold: "BLOCK_MEDIUM_AND_ABOVE"},
		},
	}

	if c.providerOptions.maxTokens > 0 {
		maxTokens := int(c.providerOptions.maxTokens)
		temp := 0.7
		req.GenerationConfig = &VertexGenerationConfig{
			MaxOutputTokens: &maxTokens,
			Temperature:     &temp,
		}
	}

	endpoint := "/" + model.ID + ":generateContent"
	resp, err := c.makeVertexRequest("POST", endpoint, req, 0)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, c.handleErrorResponse(resp)
	}

	var vertexResp VertexChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&vertexResp); err != nil {
		return nil, fmt.Errorf("failed to decode vertex response: %v", err)
	}

	return c.convertFromVertexResponse(&vertexResp)
}

func (c *FloodgateClient) stream(ctx context.Context, messages []message.Message, tools []tools.BaseTool) <-chan ProviderEvent {
	eventChan := make(chan ProviderEvent, 100)

	go func() {
		defer close(eventChan)

		// For now, implement streaming by calling send() and simulating stream events
		// Full streaming implementation would require SSE parsing
		resp, err := c.send(ctx, messages, tools)
		if err != nil {
			eventChan <- ProviderEvent{
				Type:  EventError,
				Error: err,
			}
			return
		}

		// Simulate streaming events
		eventChan <- ProviderEvent{
			Type: EventContentStart,
		}

		if resp.Content != "" {
			eventChan <- ProviderEvent{
				Type:    EventContentDelta,
				Content: resp.Content,
			}
		}

		for _, toolCall := range resp.ToolCalls {
			eventChan <- ProviderEvent{
				Type:     EventToolUseStart,
				ToolCall: &toolCall,
			}
		}

		eventChan <- ProviderEvent{
			Type:     EventComplete,
			Response: resp,
		}
	}()

	return eventChan
}

func (c *FloodgateClient) Model() catwalk.Model {
	return c.providerOptions.model(c.providerOptions.modelType)
}
