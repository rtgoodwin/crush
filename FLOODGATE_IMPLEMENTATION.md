# Floodgate Integration for Crush

This document explains how the Floodgate integration works and how to configure it.

## Overview

This implementation provides a custom Vertex AI client that works with Apple's Floodgate proxy endpoint without relying on Google's SDK. It supports both Anthropic (Claude) and Vertex AI (Gemini) models through Floodgate's proxy.

## Key Features

- **No Google SDK dependency**: Uses direct REST API calls to Floodgate's proxy
- **OAuth Bearer token authentication**: Automatically handles Apple Connect authentication
- **Dual model support**: Supports both Anthropic and Gemini models
- **Message format conversion**: Automatically converts between OpenAI and Vertex formats
- **Retry logic**: Includes automatic token refresh and retry mechanisms
- **Streaming support**: Basic streaming implementation (can be enhanced)

## How It Works

### 1. Authentication
The implementation uses Apple Connect OAuth via the `/usr/local/bin/appleconnect` command:
```bash
/usr/local/bin/appleconnect getToken -C hvys3fcwcteqrvw3qzkvtk86viuoqv \
  --token-type=oauth --interactivity-type=none -E prod -G pkce \
  -o "openid,dsid,accountname,profile,groups"
```

Tokens are cached for 8 hours and automatically refreshed on 401 responses.

### 2. Endpoints
The implementation uses two different Floodgate endpoints:

- **OpenAI-compatible endpoint** (for Claude models): `https://floodgate.g.apple.com/api/openai/v1`
- **Vertex AI endpoint** (for Gemini models): `https://floodgate.g.apple.com/api/gemini/v1/publishers/google/models`

### 3. Request/Response Handling
- **Anthropic models**: Use OpenAI-compatible format via `/chat/completions`
- **Vertex models**: Use native Vertex AI format with `/{model}:generateContent`
- Automatic message conversion between formats
- Tool calling support for both model types

### 4. Provider Detection
The implementation automatically detects Floodgate endpoints by checking if the `base_url` contains `floodgate.g.apple.com` and routes requests accordingly.

## Configuration

### Prerequisites
1. **Apple Connect**: Ensure `/usr/local/bin/appleconnect` is installed and configured
2. **Apple VPN**: Must be connected to Apple's corporate network
3. **Corporate Certificates**: Apple corporate certificates must be installed

### Example Configuration

Create a configuration file (e.g., `crush.json`) in your project directory:

```json
{
  "providers": {
    "floodgate-claude": {
      "name": "Floodgate Claude Models",
      "type": "openai",
      "base_url": "https://floodgate.g.apple.com/api/openai/v1",
      "api_key": "dummy-key-handled-by-auth",
      "models": [
        {
          "id": "aws:anthropic.claude-sonnet-4-20250514-v1:0",
          "name": "Claude Sonnet 4",
          "default_max_tokens": 4000,
          "can_reason": true
        },
        {
          "id": "aws:anthropic.claude-3-5-sonnet-20241022-v2:0", 
          "name": "Claude 3.5 Sonnet",
          "default_max_tokens": 4000,
          "can_reason": false
        }
      ]
    },
    "floodgate-gemini": {
      "name": "Floodgate Gemini Models",
      "type": "vertexai",
      "base_url": "https://floodgate.g.apple.com/api/gemini/v1/publishers/google/models",
      "api_key": "dummy-key-handled-by-auth",
      "models": [
        {
          "id": "gemini-2.5-flash",
          "name": "Gemini 2.5 Flash",
          "default_max_tokens": 8000,
          "can_reason": false
        },
        {
          "id": "gemini-2.5-pro",
          "name": "Gemini 2.5 Pro", 
          "default_max_tokens": 8000,
          "can_reason": false
        }
      ]
    }
  },
  "models": {
    "large": {
      "provider": "floodgate-claude",
      "model": "aws:anthropic.claude-sonnet-4-20250514-v1:0",
      "max_tokens": 4000
    },
    "small": {
      "provider": "floodgate-gemini", 
      "model": "gemini-2.5-flash",
      "max_tokens": 2000
    }
  }
}
```

### Configuration Details

#### Provider Types
- Use `"type": "openai"` for Claude models
- Use `"type": "vertexai"` for Gemini models

#### API Key
- The `api_key` field is required but not used (authentication is handled via Apple Connect)
- Use any dummy value like `"dummy-key-handled-by-auth"`

#### Base URLs
- Claude models: `"https://floodgate.g.apple.com/api/openai/v1"`
- Gemini models: `"https://floodgate.g.apple.com/api/gemini/v1/publishers/google/models"`

#### Model IDs
Use the exact model IDs as returned by Floodgate:
- Claude: `aws:anthropic.claude-sonnet-4-20250514-v1:0`
- Gemini: `gemini-2.5-flash`, `gemini-2.5-pro`, etc.

## Usage

Once configured, use Crush normally:

```bash
# Use the configured models
crush "Hello, how are you?"

# Switch models in TUI
# Press 'm' to open model selection dialog
```

## Implementation Details

### File Structure
```
internal/llm/provider/
├── floodgate.go          # Main Floodgate client implementation
├── provider.go           # Updated to detect Floodgate endpoints
└── ...                   # Other provider implementations
```

### Key Components

1. **FloodgateClient**: Main client implementation
   - Handles both OpenAI and Vertex API calls
   - Manages authentication and token refresh
   - Converts message formats

2. **FloodgateAuth**: Authentication manager
   - Executes Apple Connect commands
   - Caches tokens for 8 hours
   - Handles token refresh on 401 errors

3. **Message Conversion**: 
   - `convertToFloodgateMessages()`: Converts to OpenAI format
   - `convertToVertexContents()`: Converts to Vertex format
   - `convertTools()`: Converts tool definitions

4. **Provider Factory**: Updated to detect Floodgate endpoints and route appropriately

### Error Handling
- Automatic token refresh on 401 responses
- Retry logic with exponential backoff
- Proper error messages for common issues
- Network error handling

### Streaming
Basic streaming support is implemented by simulating stream events from non-streaming responses. This can be enhanced to support true server-sent events if needed.

## Troubleshooting

### Common Issues

1. **"appleconnect not found"**
   - Install Apple Connect tool at `/usr/local/bin/appleconnect`

2. **"network error - check Apple VPN connection"**
   - Ensure you're connected to Apple's corporate VPN

3. **"authentication failed"**
   - Check your Apple credentials
   - Verify corporate certificates are installed

4. **"HTTP 401: Invalid token"**
   - Token will be automatically refreshed
   - Check Apple Connect configuration

5. **"certificate error"**
   - Install Apple corporate certificates
   - Check TLS configuration

### Debug Mode
Enable debug mode in your configuration:
```json
{
  "options": {
    "debug": true
  }
}
```

This will provide detailed logging of:
- Authentication token requests
- HTTP requests and responses
- Message conversions
- Error details

## Security Considerations

- Tokens are cached in memory only (not persisted to disk)
- All communication uses HTTPS
- Uses Apple's corporate certificate infrastructure
- No API keys stored (authentication via Apple Connect)

## Future Enhancements

1. **True Streaming**: Implement server-sent events parsing for real streaming
2. **Model Discovery**: Automatically discover available models from Floodgate
3. **Advanced Tool Support**: Enhanced tool calling for Vertex AI models
4. **Connection Pooling**: HTTP connection reuse for better performance
5. **Metrics**: Request/response metrics and monitoring

## Comparison with flood Project

This implementation adapts key concepts from the flood project:

- **Authentication mechanism**: Same Apple Connect OAuth flow
- **Endpoint structure**: Uses same Floodgate URLs  
- **Message conversion**: Similar OpenAI ↔ Vertex format conversion
- **Error handling**: Same retry logic and error patterns
- **Tool calling**: Compatible tool execution patterns

However, it's redesigned to fit Crush's provider architecture and patterns.