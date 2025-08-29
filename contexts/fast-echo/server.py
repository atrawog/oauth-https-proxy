"""
FastMCP Echo Server - A simple echo server using FastMCP
"""

from fastmcp import FastMCP

# Create server with name and version
mcp = FastMCP("fast-echo", version="1.0.0")


@mcp.tool
def echo_tool(text: str) -> str:
    """Echo the input text back to the user"""
    return text


@mcp.tool
def echo_reverse(text: str) -> str:
    """Echo the input text in reverse"""
    return text[::-1]


@mcp.tool
def echo_uppercase(text: str) -> str:
    """Echo the input text in uppercase"""
    return text.upper()


@mcp.tool
def echo_lowercase(text: str) -> str:
    """Echo the input text in lowercase"""
    return text.lower()


@mcp.tool
def echo_word_count(text: str) -> str:
    """Count the number of words in the input text"""
    word_count = len(text.split())
    return f"The text contains {word_count} word(s)"


@mcp.tool
def echo_repeat(text: str, times: int = 2) -> str:
    """Repeat the input text a specified number of times"""
    return " ".join([text] * times)


@mcp.resource("echo://static")
def echo_static_resource() -> str:
    """A static echo resource"""
    return "This is a static echo resource!"


@mcp.resource("echo://info")
def echo_info() -> str:
    """Information about the echo server"""
    return """FastMCP Echo Server v1.0.0
Available tools:
- echo_tool: Echo text back
- echo_reverse: Reverse text
- echo_uppercase: Convert to uppercase
- echo_lowercase: Convert to lowercase
- echo_word_count: Count words
- echo_repeat: Repeat text"""


@mcp.resource("echo://{text}")
def echo_template(text: str) -> str:
    """Echo the input text as a resource"""
    return f"Echo resource: {text}"


@mcp.prompt("echo")
def echo_prompt(text: str) -> str:
    """Simple echo prompt"""
    return f"Please echo the following text: {text}"


@mcp.prompt("echo_analysis")
def echo_analysis_prompt(text: str) -> str:
    """Analyze the text and provide echo variations"""
    return f"""Please analyze and echo the following text in multiple ways:
Original: {text}
Reversed: {text[::-1]}
Uppercase: {text.upper()}
Lowercase: {text.lower()}
Word count: {len(text.split())} words"""


# Run the server if this file is executed directly
if __name__ == "__main__":
    # Run FastMCP with HTTP transport
    mcp.run(transport="http", host="0.0.0.0", port=3000, path="/mcp")