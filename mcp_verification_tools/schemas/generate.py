#!/usr/bin/env python
"""
Generate Pydantic models from MCP JSON schema.

This script downloads the official MCP schema and generates type-safe
Pydantic models for request/response validation.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional
import logging

# Try to import requests, provide helpful error if not available
try:
    import requests
except ImportError:
    print("Error: 'requests' package not installed.")
    print("Please install it with: pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def download_schema(version: str = "2025-06-18", force: bool = False) -> Path:
    """
    Download the MCP JSON schema from GitHub.
    
    Args:
        version: Schema version to download
        force: Force download even if file exists
    
    Returns:
        Path to downloaded schema file
    """
    schema_dir = Path(__file__).parent
    schema_path = schema_dir / f"mcp-{version}.json"
    
    # Check if already downloaded
    if schema_path.exists() and not force:
        logger.info(f"✓ Schema already exists: {schema_path}")
        return schema_path
    
    # Download from GitHub
    schema_url = (
        f"https://raw.githubusercontent.com/modelcontextprotocol/"
        f"modelcontextprotocol/refs/heads/main/schema/{version}/schema.json"
    )
    
    logger.info(f"Downloading schema from: {schema_url}")
    
    try:
        response = requests.get(schema_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to download schema: {e}")
        sys.exit(1)
    
    # Save schema
    schema_path.write_text(response.text, encoding='utf-8')
    logger.info(f"✅ Downloaded schema to: {schema_path}")
    
    return schema_path


def check_datamodel_codegen() -> bool:
    """Check if datamodel-code-generator is installed."""
    try:
        result = subprocess.run(
            ["datamodel-codegen", "--version"],
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def install_datamodel_codegen():
    """Install datamodel-code-generator if not present."""
    logger.info("Installing datamodel-code-generator...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "datamodel-code-generator[http]"],
            check=True
        )
        logger.info("✅ Installed datamodel-code-generator")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install datamodel-code-generator: {e}")
        logger.error("Please install manually: pip install datamodel-code-generator[http]")
        sys.exit(1)


def generate_models(schema_path: Path, output_path: Optional[Path] = None) -> Path:
    """
    Generate Pydantic models from JSON schema using datamodel-code-generator.
    
    Args:
        schema_path: Path to JSON schema file
        output_path: Optional custom output path
    
    Returns:
        Path to generated models file
    """
    if output_path is None:
        output_path = (
            Path(__file__).parent.parent / 
            "models" / "generated" / "mcp_schema.py"
        )
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check if datamodel-codegen is available
    if not check_datamodel_codegen():
        logger.warning("datamodel-code-generator not found")
        install_datamodel_codegen()
    
    logger.info(f"Generating models from: {schema_path}")
    logger.info(f"Output path: {output_path}")
    
    # Run datamodel-code-generator
    cmd = [
        "datamodel-codegen",
        "--input", str(schema_path),
        "--output", str(output_path),
        "--input-file-type", "jsonschema",
        # Model generation options
        "--use-schema-description",      # Include descriptions from schema
        "--field-constraints",            # Add field constraints
        "--use-double-quotes",           # Use double quotes for strings
        "--target-python-version", "3.11",
        "--output-model-type", "pydantic_v2.BaseModel",
        # Naming and structure
        "--use-title-as-name",           # Use schema titles as class names
        "--reuse-model",                 # Reuse models to avoid duplication
        "--field-include-all-keys",      # Include all keys in fields
        "--use-annotated",               # Use Annotated for field metadata
        # Additional options
        "--collapse-root-models",        # Collapse root models
        "--use-field-description",       # Include field descriptions
        "--use-default",                 # Use default values
        "--strip-default-none",          # Strip None defaults
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        if result.stderr:
            logger.warning(f"Generator warnings: {result.stderr}")
        
        logger.info(f"✅ Generated models at: {output_path}")
        
        # Add custom imports and helpers to generated file
        enhance_generated_models(output_path)
        
        return output_path
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate models: {e}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr}")
        sys.exit(1)


def enhance_generated_models(models_path: Path):
    """
    Add custom enhancements to generated models.
    
    Args:
        models_path: Path to generated models file
    """
    content = models_path.read_text()
    
    # Add header comment if not present
    header = """# Auto-generated from MCP JSON schema
# Manual edits will be overwritten on regeneration

"""
    
    if "Auto-generated from MCP JSON schema" not in content:
        # If file starts with __future__ import, add header before it
        if content.startswith("from __future__ import"):
            content = header + content
        else:
            # Find the first import or class definition
            lines = content.split('\n')
            insert_index = 0
            for i, line in enumerate(lines):
                if line.strip() and not line.startswith('#'):
                    insert_index = i
                    break
            # Insert header at the beginning
            lines.insert(0, header.rstrip())
            content = '\n'.join(lines)
        
        models_path.write_text(content)
        logger.info("✅ Enhanced generated models with header")


def validate_generated_models(models_path: Path) -> bool:
    """
    Validate that generated models can be imported.
    
    Args:
        models_path: Path to generated models
    
    Returns:
        True if models are valid
    """
    logger.info("Validating generated models...")
    
    # Try to import the module
    import importlib.util
    spec = importlib.util.spec_from_file_location("mcp_schema", models_path)
    
    if spec is None or spec.loader is None:
        logger.error("Failed to load module spec")
        return False
    
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Check for expected classes
        expected_classes = [
            "InitializeRequest",
            "InitializeResponse",
            "Tool",
            "ContentBlock"
        ]
        
        for class_name in expected_classes:
            if not hasattr(module, class_name):
                logger.warning(f"Missing expected class: {class_name}")
        
        logger.info("✅ Models validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to import generated models: {e}")
        return False


def main():
    """Main entry point for schema generation."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate Pydantic models from MCP JSON schema"
    )
    parser.add_argument(
        "--version",
        default="2025-06-18",
        help="MCP schema version (default: 2025-06-18)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force download even if schema exists"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Custom output path for generated models"
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip validation of generated models"
    )
    
    args = parser.parse_args()
    
    logger.info("=== MCP Schema Model Generation ===\n")
    
    # Download schema
    schema_path = download_schema(version=args.version, force=args.force)
    
    # Generate models
    models_path = generate_models(schema_path, output_path=args.output)
    
    # Validate models
    if not args.skip_validation:
        if validate_generated_models(models_path):
            logger.info("\n✅ Model generation complete!")
        else:
            logger.error("\n❌ Model validation failed")
            sys.exit(1)
    else:
        logger.info("\n✅ Model generation complete (validation skipped)")
    
    logger.info(f"\nGenerated models are available at: {models_path}")
    logger.info("\nYou can now import them in your tests:")
    logger.info("  from mcp_verification_tools.models.generated.mcp_schema import *")


if __name__ == "__main__":
    main()