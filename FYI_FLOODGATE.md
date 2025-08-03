# Floodgate Integration Specification

A comprehensive technical specification for integrating Apple's internal Floodgate service for Anthropic Claude and Google Vertex AI models. This specification is language-agnostic and applicable to Go, Python, Swift, and other platforms.

## Table of Contents
- [Overview](#overview)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Anthropic/Claude Integration](#anthropicClaude-integration)
- [Vertex AI Integration](#vertex-ai-integration)
- [Error Handling](#error-handling)
- [Implementation Examples](#implementation-examples)
- [Security Considerations](#security-considerations)

## Overview

Apple's Floodgate service provides proxy access to multiple LLM providers with unified authentication. The service offers two primary integration paths:

1. **OpenAI-Compatible API** - Primary path for Anthropic Claude models
2. **Vertex AI Proxy** - Alternative path for Google Gemini models  

Both paths use Apple's internal AppleConnect authentication system.

## Authentication

### AppleConnect Integration

#### For Swift Applications

**Framework Requirements:**
```swift
// Import framework
#if canImport(AppleConnectClient)
import AppleConnectClient
#endif

// Platform-specific context
#if os(macOS)
public typealias AuthenticationContext = ACDesktopAuthenticationContext
#else
public typealias AuthenticationContext = ACMobileAuthenticationContext
#endif
```

**Authentication Flow:**
```swift
// Configuration
let context = AuthenticationContext()
context.environment = .production  // or .UAT for testing

let request = ACAuthenticationRequest()
request.oauthClientID = "hvys3fcwcteqrvw3qzkvtk86viuoqv"
request.authType = .OAuth
request.interactivityType = .silentPreferred
request.oauthScopes = ["openid", "dsid", "accountname", "profile", "groups"]
request.oauthGrantType = .PKCE

// Execute authentication
let response = await context.authenticate(with: request)
```

#### For Non-Swift Applications

**Binary Integration:**
- Use `appleconnect` binary for token retrieval
- Location: `/usr/local/bin/appleconnect` (typical installation)
- Command: `appleconnect auth --client-id hvys3fcwcteqrvw3qzkvtk86viuoqv --scopes openid,dsid,accountname,profile,groups`

**Token Processing:**
```python
# Example Python implementation
def process_apple_token(raw_token: str) -> str:
    """
    Extract OAuth token from AppleConnect service ticket
    Format: "key:actual_token,additional_data"
    """
    # Split by ':' and take second part
    parts = raw_token.split(':', 1)
    if len(parts) != 2:
        raise ValueError("Invalid token format")
    
    # Split by ',' and take first part
    token_part = parts[1].split(',')[0]
    return token_part
```

```go
// Example Go implementation
func ProcessAppleToken(rawToken string) (string, error) {
    // Split by ':' and take second part
    parts := strings.SplitN(rawToken, ":", 2)
    if len(parts) != 2 {
        return "", fmt.Errorf("invalid token format")
    }
    
    // Split by ',' and take first part
    tokenPart := strings.SplitN(parts[1], ",", 2)[0]
    return tokenPart, nil
}
```

## API Endpoints

### Base URLs

- **OpenAI-Compatible (Primary)**: `https://floodgate.g.apple.com/api/openai/v1`
- **Vertex AI Proxy**: `https://floodgate.g.apple.com/api/gemini/v1/publishers/google/models`
- **Batch Processing**: `https://floodgate.g.apple.com/api/batch/v1`

### Common Headers

```http
Authorization: Bearer {processed_token}
Content-Type: application/json
User-Agent: {your-app-name}/{version}
```

## Anthropic/Claude Integration

### Available Models

**Primary Claude 4 Models:**
- `aws:anthropic.claude-sonnet-4-20250514-v1:0` → "Claude 4 Sonnet"
- `aws:anthropic.claude-opus-4-20250514-v1:0` → "Claude 4 Opus"

**Claude 3.x Models:**
- `aws:anthropic.claude-3-7-sonnet-20250219-v1:0` → "Claude 3.7 Sonnet"
- `aws:anthropic.claude-3-5-sonnet-20241022-v2:0` → "Claude 3.5 Sonnet (New)"
- `aws:anthropic.claude-3-5-sonnet-20240620-v1:0` → "Claude 3.5 Sonnet"
- `aws:anthropic.claude-3-5-haiku-20241022-v1:0` → "Claude 3.5 Haiku"

### OpenAI-Compatible Endpoints

#### List Models
```http
GET /models
Authorization: Bearer {token}
```

**Response Format:**
```json
{
  "object": "list",
  "data": [
    {
      "id": "aws:anthropic.claude-sonnet-4-20250514-v1:0",
      "object": "model",
      "owned_by": "anthropic"
    }
  ]
}
```

#### Chat Completions
```http
POST /chat/completions
Authorization: Bearer {token}
Content-Type: application/json
```

**Request Format:**
```json
{
  "model": "aws:anthropic.claude-sonnet-4-20250514-v1:0",
  "messages": [
    {
      "role": "user", 
      "content": "Hello, Claude!"
    }
  ],
  "temperature": 0.1,
  "max_tokens": 4000,
  "stream": false,
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get weather information",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {"type": "string"}
          }
        }
      }
    }
  ]
}
```

**Response Format:**
```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help you today?",
        "tool_calls": [
          {
            "id": "call_123",
            "type": "function", 
            "function": {
              "name": "get_weather",
              "arguments": "{\"location\": \"San Francisco\"}"
            }
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ],
  "usage": {
    "prompt_tokens": 20,
    "completion_tokens": 30,
    "total_tokens": 50
  }
}
```

#### Streaming Chat Completions
```http
POST /chat/completions
Authorization: Bearer {token}
Content-Type: application/json
```

**Request:** Same as above with `"stream": true`

**Response:** Server-sent events stream:
```
data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"delta":{"content":"!"}}]}

data: [DONE]
```

### Tool Calling Support

**Tool Definition Format:**
```json
{
  "type": "function",
  "function": {
    "name": "function_name",
    "description": "Function description",
    "parameters": {
      "type": "object",
      "properties": {
        "param1": {"type": "string", "description": "Parameter description"},
        "param2": {"type": "number", "enum": [1, 2, 3]}
      },
      "required": ["param1"]
    }
  }
}
```

**Tool Call Response:**
```json
{
  "tool_calls": [
    {
      "id": "call_abc123",
      "type": "function",
      "function": {
        "name": "function_name",
        "arguments": "{\"param1\": \"value\"}"
      }
    }
  ]
}
```

**Tool Result Message:**
```json
{
  "role": "tool",
  "tool_call_id": "call_abc123",
  "content": "Function execution result"
}
```

## Vertex AI Integration

### Available Models

**Primary Gemini Models:**
- `gemini-2.5-flash` → "Gemini 2.5 Flash"
- `gemini-2.5-pro` → "Gemini 2.5 Pro"
- `gemini-2.0-flash` → "Gemini 2.0 Flash"
- `gemini-1.5-flash` → "Gemini 1.5 Flash"
- `gemini-1.5-pro` → "Gemini 1.5 Pro"

### Vertex AI Endpoints

#### Model Discovery
```http
GET /
Authorization: Bearer {token}
```

**Response Format:**
```json
{
  "models": [
    {
      "name": "gemini-2.5-flash",
      "displayName": "Gemini 2.5 Flash",
      "description": "Fast and efficient model",
      "inputTokenLimit": 1000000,
      "outputTokenLimit": 8192,
      "supportedActions": ["generateContent"]
    }
  ]
}
```

#### Content Generation
```http
POST /{model}:generateContent
Authorization: Bearer {token}
Content-Type: application/json
```

**Request Format:**
```json
{
  "contents": [
    {
      "role": "user",
      "parts": [
        {
          "text": "Hello, Gemini!"
        }
      ]
    }
  ],
  "generationConfig": {
    "temperature": 0.1,
    "maxOutputTokens": 8000,
    "topK": 32,
    "topP": 1.0
  },
  "safetySettings": [
    {
      "category": "HARM_CATEGORY_HARASSMENT",
      "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
      "category": "HARM_CATEGORY_HATE_SPEECH", 
      "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
      "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
      "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
      "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
      "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    }
  ]
}
```

**Response Format:**
```json
{
  "candidates": [
    {
      "content": {
        "role": "model",
        "parts": [
          {
            "text": "Hello! How can I assist you today?"
          }
        ]
      },
      "finishReason": "STOP",
      "safetyRatings": [
        {
          "category": "HARM_CATEGORY_HARASSMENT",
          "probability": "NEGLIGIBLE"
        }
      ]
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 4,
    "candidatesTokenCount": 12,
    "totalTokenCount": 16
  }
}
```

### Tool/Function Calling

**Tool Definition Format:**
```json
{
  "tools": [
    {
      "functionDeclarations": [
        {
          "name": "get_weather",
          "description": "Get weather information for a location",
          "parameters": {
            "type": "object",
            "properties": {
              "location": {
                "type": "string",
                "description": "City name"
              }
            },
            "required": ["location"]
          }
        }
      ]
    }
  ]
}
```

**Function Call Response:**
```json
{
  "candidates": [
    {
      "content": {
        "role": "model",
        "parts": [
          {
            "functionCall": {
              "name": "get_weather",
              "args": {
                "location": "San Francisco"
              }
            }
          }
        ]
      }
    }
  ]
}
```

**Function Response Message:**
```json
{
  "contents": [
    {
      "role": "user",
      "parts": [
        {
          "functionResponse": {
            "name": "get_weather",
            "response": {
              "result": "Sunny, 72°F with light breeze"
            }
          }
        }
      ]
    }
  ]
}
```

### Message Conversion

**OpenAI to Vertex Format:**
```python
def convert_openai_to_vertex(messages):
    """Convert OpenAI messages to Vertex contents format"""
    contents = []
    for message in messages:
        role = "user" if message["role"] in ["user", "system"] else "model"
        contents.append({
            "role": role,
            "parts": [{"text": message["content"]}]
        })
    return contents
```

**Vertex to OpenAI Format:**
```python
def convert_vertex_to_openai(vertex_response):
    """Convert Vertex response to OpenAI format"""
    if not vertex_response.get("candidates"):
        raise ValueError("No candidates in response")
    
    candidate = vertex_response["candidates"][0]
    content = candidate["content"]["parts"][0]["text"]
    
    return {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": candidate.get("finishReason", "stop").lower()
        }],
        "usage": {
            "prompt_tokens": vertex_response.get("usageMetadata", {}).get("promptTokenCount", 0),
            "completion_tokens": vertex_response.get("usageMetadata", {}).get("candidatesTokenCount", 0),
            "total_tokens": vertex_response.get("usageMetadata", {}).get("totalTokenCount", 0)
        }
    }
```

## Error Handling

### Common HTTP Status Codes

- **200**: Success
- **400**: Bad Request (invalid parameters)
- **401**: Unauthorized (invalid/expired token)
- **403**: Forbidden (insufficient permissions)
- **429**: Rate Limited
- **500**: Internal Server Error
- **503**: Service Unavailable

### Error Response Format

**OpenAI-Compatible Errors:**
```json
{
  "error": {
    "message": "Invalid model specified",
    "type": "invalid_request_error",
    "code": "model_not_found"
  }
}
```

**Vertex AI Errors:**
```json
{
  "error": {
    "code": 400,
    "message": "Invalid request format",
    "status": "INVALID_ARGUMENT"
  }
}
```

### Retry Strategy

**Recommended Retry Policy:**
```python
class RetryPolicy:
    max_retries = 3
    backoff_factor = 2.0  # Exponential backoff
    retry_status_codes = [429, 500, 502, 503, 504]
    
    def should_retry(self, status_code, attempt):
        return (status_code in self.retry_status_codes and 
                attempt < self.max_retries)
    
    def get_delay(self, attempt):
        return self.backoff_factor ** attempt
```

### Token Refresh Logic

```python
async def ensure_valid_token(self):
    """Ensure token is valid, refresh if necessary"""
    try:
        # Test token with a lightweight request
        await self.list_models()
        return self.current_token
    except UnauthorizedError:
        # Token expired, refresh
        self.current_token = await self.authenticate()
        return self.current_token
```

## Implementation Examples

### Python Implementation

```python
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional

class FloodgateClient:
    def __init__(self, auth_provider):
        self.auth_provider = auth_provider
        self.base_url = "https://floodgate.g.apple.com/api/openai/v1"
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def _get_headers(self) -> Dict[str, str]:
        token = await self.auth_provider.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "FloodgateClient/1.0"
        }
    
    async def list_models(self) -> List[Dict[str, Any]]:
        headers = await self._get_headers()
        async with self.session.get(f"{self.base_url}/models", headers=headers) as response:
            response.raise_for_status()
            data = await response.json()
            return data["data"]
    
    async def chat_completion(self, messages: List[Dict], model: str, **kwargs) -> Dict[str, Any]:
        headers = await self._get_headers()
        payload = {
            "model": model,
            "messages": messages,
            **kwargs
        }
        
        async with self.session.post(f"{self.base_url}/chat/completions", 
                                   json=payload, headers=headers) as response:
            response.raise_for_status()
            return await response.json()

# Usage example
async def main():
    auth_provider = AppleConnectAuthProvider()
    
    async with FloodgateClient(auth_provider) as client:
        models = await client.list_models()
        print(f"Available models: {[m['id'] for m in models]}")
        
        response = await client.chat_completion(
            messages=[{"role": "user", "content": "Hello!"}],
            model="aws:anthropic.claude-sonnet-4-20250514-v1:0",
            temperature=0.1,
            max_tokens=1000
        )
        
        print(f"Response: {response['choices'][0]['message']['content']}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Go Implementation

```go
package floodgate

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type Client struct {
    baseURL      string
    authProvider AuthProvider
    httpClient   *http.Client
}

type ChatMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

type ChatRequest struct {
    Model       string        `json:"model"`
    Messages    []ChatMessage `json:"messages"`
    Temperature *float64      `json:"temperature,omitempty"`
    MaxTokens   *int         `json:"max_tokens,omitempty"`
    Stream      bool         `json:"stream,omitempty"`
}

type ChatResponse struct {
    Choices []struct {
        Message struct {
            Role    string `json:"role"`
            Content string `json:"content"`
        } `json:"message"`
        FinishReason string `json:"finish_reason"`
    } `json:"choices"`
    Usage struct {
        PromptTokens     int `json:"prompt_tokens"`
        CompletionTokens int `json:"completion_tokens"`
        TotalTokens      int `json:"total_tokens"`
    } `json:"usage"`
}

func NewClient(authProvider AuthProvider) *Client {
    return &Client{
        baseURL:      "https://floodgate.g.apple.com/api/openai/v1",
        authProvider: authProvider,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (c *Client) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
    token, err := c.authProvider.GetToken(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get token: %w", err)
    }
    
    jsonData, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }
    
    httpReq, err := http.NewRequestWithContext(ctx, "POST", 
        c.baseURL+"/chat/completions", bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    httpReq.Header.Set("Authorization", "Bearer "+token)
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("User-Agent", "FloodgateClient/1.0")
    
    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("API error: %d", resp.StatusCode)
    }
    
    var chatResp ChatResponse
    if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }
    
    return &chatResp, nil
}

// Usage example
func main() {
    authProvider := NewAppleConnectAuthProvider()
    client := NewClient(authProvider)
    
    response, err := client.ChatCompletion(context.Background(), ChatRequest{
        Model: "aws:anthropic.claude-sonnet-4-20250514-v1:0",
        Messages: []ChatMessage{
            {Role: "user", Content: "Hello, Claude!"},
        },
        Temperature: &[]float64{0.1}[0],
        MaxTokens:   &[]int{1000}[0],
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Response: %s\n", response.Choices[0].Message.Content)
}
```

## Security Considerations

### Token Management
- **Never log tokens** in plain text
- **Store tokens securely** (encrypted at rest)
- **Implement token refresh** on 401 errors
- **Use short-lived tokens** when possible

### Request Security
- **Always use HTTPS** for API calls
- **Validate response data** before processing
- **Implement proper timeout** handling
- **Use connection pooling** for efficiency

### Error Information
- **Don't expose tokens** in error messages
- **Log errors appropriately** (sanitize sensitive data)
- **Implement proper fallback** mechanisms

### Network Security
- **Certificate pinning** for production applications
- **Proxy support** for corporate environments
- **Rate limiting** to avoid service abuse

## Configuration Examples

### Environment Variables
```bash
# Authentication
FLOODGATE_CLIENT_ID=hvys3fcwcteqrvw3qzkvtk86viuoqv
FLOODGATE_ENVIRONMENT=production  # or 'uat'

# API Settings
FLOODGATE_BASE_URL=https://floodgate.g.apple.com/api/openai/v1
FLOODGATE_TIMEOUT=30
FLOODGATE_MAX_RETRIES=3

# Model Preferences
FLOODGATE_DEFAULT_MODEL=aws:anthropic.claude-sonnet-4-20250514-v1:0
FLOODGATE_DEFAULT_TEMPERATURE=0.1
FLOODGATE_DEFAULT_MAX_TOKENS=4000
```

### Configuration File (YAML)
```yaml
floodgate:
  authentication:
    client_id: "hvys3fcwcteqrvw3qzkvtk86viuoqv"
    environment: "production"
    scopes: ["openid", "dsid", "accountname", "profile", "groups"]
    
  api:
    openai_base_url: "https://floodgate.g.apple.com/api/openai/v1"
    vertex_base_url: "https://floodgate.g.apple.com/api/gemini/v1/publishers/google/models"
    timeout: 30
    max_retries: 3
    retry_backoff: 2.0
    
  models:
    claude:
      default: "aws:anthropic.claude-sonnet-4-20250514-v1:0"
      aliases:
        claude-4-sonnet: "aws:anthropic.claude-sonnet-4-20250514-v1:0"
        claude-4-opus: "aws:anthropic.claude-opus-4-20250514-v1:0"
        claude-3.5-sonnet: "aws:anthropic.claude-3-5-sonnet-20241022-v2:0"
        
    gemini:
      default: "gemini-2.5-flash"
      aliases:
        gemini-flash: "gemini-2.5-flash"
        gemini-pro: "gemini-2.5-pro"
        
  defaults:
    temperature: 0.1
    max_tokens: 4000
    stream: false
```

This specification provides a comprehensive foundation for integrating with Apple's Floodgate service across multiple programming languages and platforms, supporting both Anthropic Claude and Google Vertex AI models through unified authentication.