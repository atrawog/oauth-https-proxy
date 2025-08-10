"""Main entry point for MCP HTTP Echo Server."""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

from .server import MCPEchoServer

# Load environment variables
load_dotenv()


def parse_supported_versions(versions_str: str) -> List[str]:
    """Parse comma-separated supported protocol versions.
    
    Args:
        versions_str: Comma-separated version string
        
    Returns:
        List of version strings
    """
    if not versions_str:
        return []
    return [v.strip() for v in versions_str.split(",") if v.strip()]


def detect_mode() -> str:
    """Auto-detect the best mode based on environment.
    
    Returns:
        "stateless" or "stateful"
    """
    # Check for serverless/container environments that benefit from stateless
    if any([
        os.getenv("KUBERNETES_SERVICE_HOST"),  # Kubernetes
        os.getenv("LAMBDA_RUNTIME_DIR"),       # AWS Lambda
        os.getenv("FUNCTIONS_WORKER_RUNTIME"), # Azure Functions
        os.getenv("GOOGLE_FUNCTION_TARGET"),   # Google Cloud Functions
        os.getenv("VERCEL"),                   # Vercel
    ]):
        return "stateless"
    
    # Default to stateful for development
    return "stateful"


def setup_logging(debug: bool, log_file: Optional[str] = None):
    """Set up logging configuration.
    
    Args:
        debug: Enable debug logging
        log_file: Optional log file path
    """
    log_level = logging.DEBUG if debug else logging.INFO
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers
    )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MCP HTTP Echo Server - Dual-mode echo server with 21 comprehensive debugging tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  auto      - Automatically detect based on environment
  stateful  - Full session management and state persistence
  stateless - No session persistence, horizontally scalable

Examples:
  # Run in auto-detected mode
  mcp-http-echo-server
  
  # Run in stateless mode for production
  mcp-http-echo-server --mode stateless --port 8080
  
  # Run in stateful mode with debug logging
  mcp-http-echo-server --mode stateful --debug
  
  # Run with custom protocol versions
  mcp-http-echo-server --protocol-versions "2025-06-18,2025-03-26"

Environment Variables:
  MCP_ECHO_HOST              - Host to bind to (default: 0.0.0.0)
  MCP_ECHO_PORT              - Port to bind to (default: 3000)
  MCP_ECHO_DEBUG             - Enable debug mode (true/false)
  MCP_MODE                   - Server mode (auto/stateful/stateless)
  MCP_SESSION_TIMEOUT        - Session timeout in seconds (default: 3600)
  MCP_PROTOCOL_VERSIONS      - Comma-separated protocol versions
  MCP_STATELESS             - Force stateless mode (true/false)
        """
    )
    
    # Server options
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_ECHO_HOST", "0.0.0.0"),
        help="Host to bind to (default: 0.0.0.0, env: MCP_ECHO_HOST)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_ECHO_PORT", "3000")),
        help="Port to bind to (default: 3000, env: MCP_ECHO_PORT)"
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--mode",
        choices=["auto", "stateful", "stateless"],
        default=os.getenv("MCP_MODE", "auto"),
        help="Server mode (default: auto, env: MCP_MODE)"
    )
    mode_group.add_argument(
        "--stateless",
        action="store_true",
        help="Run in stateless mode (shorthand for --mode stateless)"
    )
    mode_group.add_argument(
        "--stateful",
        action="store_true",
        help="Run in stateful mode (shorthand for --mode stateful)"
    )
    
    # Protocol options
    parser.add_argument(
        "--protocol-versions",
        default=os.getenv("MCP_PROTOCOL_VERSIONS_SUPPORTED", "2025-06-18,2025-03-26,2024-11-05"),
        help="Comma-separated list of supported protocol versions (env: MCP_PROTOCOL_VERSIONS_SUPPORTED)"
    )
    parser.add_argument(
        "--session-timeout",
        type=int,
        default=int(os.getenv("MCP_SESSION_TIMEOUT", "3600")),
        help="Session timeout in seconds for stateful mode (default: 3600, env: MCP_SESSION_TIMEOUT)"
    )
    
    # Transport options
    parser.add_argument(
        "--transport",
        choices=["http", "stdio", "sse"],
        default="http",
        help="Transport type (default: http)"
    )
    
    # Debug options
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.getenv("MCP_ECHO_DEBUG", "").lower() in ("true", "1", "yes"),
        help="Enable debug mode (default: False, env: MCP_ECHO_DEBUG)"
    )
    parser.add_argument(
        "--log-file",
        default=os.getenv("MCP_LOG_FILE"),
        help="Log file path (env: MCP_LOG_FILE)"
    )
    
    # Info options
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all available tools and exit"
    )
    
    args = parser.parse_args()
    
    # Handle info options
    if args.list_tools:
        print("MCP HTTP Echo Server - Available Tools\n")
        print("Echo Tools (2):")
        print("  echo          - Echo back messages with context")
        print("  replayLastEcho - Replay last echo (stateful only)")
        print("\nDebug Tools (4):")
        print("  printHeader    - Display HTTP headers")
        print("  requestTiming  - Show request timing metrics")
        print("  corsAnalysis   - Analyze CORS configuration")
        print("  environmentDump - Display environment config")
        print("\nAuth Tools (3):")
        print("  bearerDecode   - Decode JWT tokens")
        print("  authContext    - Display auth context")
        print("  whoIStheGOAT   - AI excellence analyzer")
        print("\nSystem Tools (2):")
        print("  healthProbe    - Deep health check")
        print("  sessionInfo    - Session information")
        print("\nState Tools (10):")
        print("  stateInspector   - Inspect state storage")
        print("  sessionHistory   - Show session history")
        print("  stateManipulator - Manipulate state")
        print("  sessionCompare   - Compare sessions")
        print("  sessionTransfer  - Export/import sessions")
        print("  stateBenchmark   - Benchmark state ops")
        print("  sessionLifecycle - Session lifecycle info")
        print("  stateValidator   - Validate state consistency")
        print("  requestTracer    - Trace request flow")
        print("  modeDetector     - Detect operational mode")
        print("\nTotal: 21 tools")
        sys.exit(0)
    
    # Determine mode
    if args.stateless:
        stateless_mode = True
    elif args.stateful:
        stateless_mode = False
    elif args.mode == "auto":
        detected_mode = detect_mode()
        stateless_mode = detected_mode == "stateless"
        if args.debug:
            print(f"Auto-detected mode: {detected_mode}")
    else:
        stateless_mode = args.mode == "stateless"
    
    # Check for environment override
    if os.getenv("MCP_STATELESS", "").lower() == "true":
        stateless_mode = True
        if args.debug:
            print("Mode overridden by MCP_STATELESS environment variable")
    
    # Parse supported versions
    supported_versions = parse_supported_versions(args.protocol_versions)
    if not supported_versions:
        print("Error: No supported protocol versions specified", file=sys.stderr)
        sys.exit(1)
    
    # Set up logging
    setup_logging(args.debug, args.log_file)
    logger = logging.getLogger(__name__)
    
    # Print startup information
    print(f"🚀 MCP HTTP Echo Server v1.0.0")
    print(f"Mode: {'STATELESS' if stateless_mode else 'STATEFUL'}")
    print(f"Transport: {args.transport.upper()}")
    print(f"Address: {args.host}:{args.port}")
    print(f"Debug: {'Enabled' if args.debug else 'Disabled'}")
    print(f"Protocol versions: {', '.join(supported_versions)}")
    if not stateless_mode:
        print(f"Session timeout: {args.session_timeout}s")
    print(f"Tools: 21 comprehensive debugging tools")
    print()
    
    # Create server
    try:
        server = MCPEchoServer(
            stateless_mode=stateless_mode,
            session_timeout=args.session_timeout,
            debug=args.debug,
            supported_versions=supported_versions
        )
        
        # Run server
        logger.info(
            "Starting server in %s mode on %s:%d",
            "STATELESS" if stateless_mode else "STATEFUL",
            args.host,
            args.port
        )
        
        # Run the server
        server.run(
            host=args.host,
            port=args.port,
            transport=args.transport
        )
        
    except KeyboardInterrupt:
        print("\n⏹️ Server shutdown requested")
        logger.info("Server shutdown by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Server error: {e}", file=sys.stderr)
        logger.error("Server error", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()