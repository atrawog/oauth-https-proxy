# FastMCP Echo Server

A simple echo server built with FastMCP framework that provides various text manipulation tools.

## Features

- **Tools**:
  - `echo_tool`: Echo text back
  - `echo_reverse`: Reverse text
  - `echo_uppercase`: Convert to uppercase
  - `echo_lowercase`: Convert to lowercase
  - `echo_word_count`: Count words in text
  - `echo_repeat`: Repeat text multiple times

- **Resources**:
  - `echo://static`: Static echo resource
  - `echo://info`: Server information
  - `echo://{text}`: Dynamic text resource

- **Prompts**:
  - `echo`: Simple echo prompt
  - `echo_analysis`: Analyze text with multiple variations

## Installation

```bash
pip install -e .
```

## Running

```bash
# Using uvicorn directly
uvicorn server:mcp --host 0.0.0.0 --port 3000

# Or with FastMCP's built-in runner
python server.py
```

## Docker

Build and run with Docker:

```bash
docker build -t fast-echo-mcp .
docker run -p 3000:3000 fast-echo-mcp
```

## Testing

Access the MCP endpoint at:
- HTTP: http://localhost:3000/mcp
- HTTPS: https://fast-echo.atratest.org/mcp