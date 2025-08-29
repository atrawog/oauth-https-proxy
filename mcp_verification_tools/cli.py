#!/usr/bin/env python
"""
Command-line interface for MCP Verification Tools.

Provides commands for:
- Validating MCP endpoints
- Listing available tests
- Generating compliance reports
- Running stress tests
- Comparing endpoints
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional, List
import logging

import click

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

# Try to import rich for better output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    console = None
    RICH_AVAILABLE = False
    print("Note: Install 'rich' for better output: pip install rich")


from .core.registry import TestCategory, test_registry
from .core.runner import TestRunner, StressTestRunner
from .models.config import TestConfig
from .reporters.yaml_reporter import YAMLReporter
from .__version__ import __version__


@click.group()
@click.version_option(version=__version__)
def cli():
    """
    MCP Verification Tools - Comprehensive MCP endpoint compliance testing.
    
    Test MCP endpoints against the official specification with detailed
    reporting and remediation guidance.
    
    Examples:
    
    \b
    # Validate a single endpoint
    mcp-verify validate https://example.com/mcp
    
    \b
    # Validate multiple endpoints
    mcp-verify validate https://endpoint1.com/mcp https://endpoint2.com/mcp
    
    \b
    # Run specific category of tests
    mcp-verify validate https://example.com/mcp --category session
    
    \b
    # Generate verbose report with passing tests
    mcp-verify validate https://example.com/mcp --verbose --output report.yaml
    
    \b
    # List all available tests
    mcp-verify list-tests
    
    \b
    # Run stress test
    mcp-verify stress https://example.com/mcp --sessions 100 --duration 60
    """
    pass


@cli.command()
@click.argument('endpoints', nargs=-1, required=True)
@click.option(
    '--category', '-c',
    type=click.Choice([c.value for c in TestCategory] + ['all']),
    default='all',
    help='Test category to run'
)
@click.option(
    '--tags', '-t',
    multiple=True,
    help='Filter tests by tags (can specify multiple)'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    default='mcp-compliance-report.yaml',
    help='Output file path for report'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Include passing tests in report'
)
@click.option(
    '--parallel/--sequential',
    default=True,
    help='Run tests in parallel (default) or sequential'
)
@click.option(
    '--fail-fast',
    is_flag=True,
    help='Stop on first critical failure'
)
@click.option(
    '--strict',
    is_flag=True,
    help='Fail on any non-compliance'
)
@click.option(
    '--timeout',
    type=int,
    default=30,
    help='Default timeout for tests in seconds'
)
@click.option(
    '--no-evidence',
    is_flag=True,
    help='Exclude evidence from report'
)
def validate(endpoints, category, tags, output, verbose, parallel, 
             fail_fast, strict, timeout, no_evidence):
    """
    Validate MCP endpoints for specification compliance.
    
    Run comprehensive compliance tests against one or more MCP endpoints
    and generate detailed YAML reports with remediation guidance.
    """
    _print_header("MCP Compliance Validation")
    
    # Discover available tests
    discovered = test_registry.discover_tests()
    _print_info(f"Discovered {discovered} tests")
    
    # Process each endpoint
    all_suites = []
    
    for endpoint in endpoints:
        _print_section(f"Testing: {endpoint}")
        
        # Create configuration
        config = TestConfig(
            endpoint=endpoint,
            categories=[category] if category != 'all' else None,
            tags=list(tags) if tags else None,
            parallel=parallel,
            fail_fast=fail_fast,
            strict=strict,
            verbose=verbose,
            timeout=timeout,
            include_passing=verbose,
            include_evidence=not no_evidence
        )
        
        # Create runner
        runner = TestRunner(config)
        
        # Set progress callback if rich is available
        if RICH_AVAILABLE:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            )
            task = None
            
            def progress_callback(result, suite):
                nonlocal task
                if task is None:
                    task = progress.add_task(
                        f"Running tests...", 
                        total=None
                    )
                
                icon = "✅" if result.is_success() else "❌"
                progress.update(
                    task,
                    description=f"{icon} [{result.test_id}] {result.test_name}"
                )
            
            runner.set_progress_callback(progress_callback)
            
            # Run tests with progress
            with progress:
                suite = asyncio.run(runner.run_tests(
                    category=TestCategory(category) if category != 'all' else None,
                    tags=list(tags) if tags else None
                ))
        else:
            # Run without progress bar
            suite = asyncio.run(runner.run_tests(
                category=TestCategory(category) if category != 'all' else None,
                tags=list(tags) if tags else None
            ))
        
        all_suites.append(suite)
        
        # Display summary for this endpoint
        _display_endpoint_summary(suite)
    
    # Generate combined report
    _print_section("Generating Report")
    
    reporter = YAMLReporter(
        include_passing=verbose,
        include_evidence=not no_evidence
    )
    
    # If multiple endpoints, create comparison report
    if len(all_suites) > 1:
        _print_info("Creating comparison report for multiple endpoints")
        # For now, just report the first one (could be enhanced)
        reporter.generate_report(all_suites[0], output_path=output)
    else:
        reporter.generate_report(all_suites[0], output_path=output)
    
    _print_success(f"Report saved to: {output}")
    
    # Exit with appropriate code
    any_failed = any(s.failed > 0 for s in all_suites)
    if strict and any_failed:
        sys.exit(1)
    elif any(s.compliance_score < 50 for s in all_suites):
        sys.exit(2)
    else:
        sys.exit(0)


@cli.command('list-tests')
@click.option(
    '--category', '-c',
    type=click.Choice([c.value for c in TestCategory]),
    help='Filter by category'
)
@click.option(
    '--tags', '-t',
    multiple=True,
    help='Filter by tags'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['table', 'list', 'json']),
    default='table',
    help='Output format'
)
def list_tests(category, tags, format):
    """List all available MCP compliance tests."""
    
    _print_header("Available MCP Tests")
    
    # Discover tests
    test_registry.discover_tests()
    
    # Get filtered tests
    tests = test_registry.get_tests(
        category=TestCategory(category) if category else None,
        tags=list(tags) if tags else None
    )
    
    if not tests:
        _print_warning("No tests found matching filters")
        return
    
    # Display based on format
    if format == 'table' and RICH_AVAILABLE:
        table = Table(title=f"MCP Compliance Tests ({len(tests)} total)")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Category", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Tags", style="green")
        
        for test in tests:
            meta = test['metadata']
            table.add_row(
                meta.test_id,
                meta.name,
                meta.category.value,
                meta.severity.value,
                ', '.join(meta.tags or [])
            )
        
        console.print(table)
        
    elif format == 'json':
        import json
        data = []
        for test in tests:
            meta = test['metadata']
            data.append({
                'test_id': meta.test_id,
                'name': meta.name,
                'category': meta.category.value,
                'severity': meta.severity.value,
                'tags': meta.tags,
                'description': meta.description
            })
        print(json.dumps(data, indent=2))
        
    else:
        # Simple list format
        for test in tests:
            meta = test['metadata']
            print(f"{meta.test_id}: {meta.name}")
            print(f"  Category: {meta.category.value}")
            print(f"  Severity: {meta.severity.value}")
            if meta.tags:
                print(f"  Tags: {', '.join(meta.tags)}")
            print()
    
    _print_info(f"Total tests: {len(tests)}")


@cli.command()
@click.argument('endpoint')
@click.option(
    '--sessions', '-s',
    type=int,
    default=50,
    help='Number of concurrent sessions'
)
@click.option(
    '--duration', '-d',
    type=int,
    default=60,
    help='Test duration in seconds'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    help='Save results to file'
)
def stress(endpoint, sessions, duration, output):
    """
    Run stress tests on an MCP endpoint.
    
    Tests the endpoint's ability to handle multiple concurrent sessions
    and high request rates.
    """
    _print_header("MCP Stress Testing")
    _print_info(f"Endpoint: {endpoint}")
    _print_info(f"Sessions: {sessions}")
    _print_info(f"Duration: {duration} seconds")
    
    # Create stress test runner
    config = TestConfig(endpoint=endpoint)
    runner = StressTestRunner(config)
    
    # Run stress test
    _print_section("Running stress test...")
    metrics = asyncio.run(runner.run_stress_test(duration, sessions))
    
    # Display results
    _print_section("Stress Test Results")
    print(f"Total Requests: {metrics['total_requests']}")
    print(f"Successful: {metrics['successful_requests']}")
    print(f"Failed: {metrics['failed_requests']}")
    print(f"Requests/Second: {metrics['requests_per_second']:.2f}")
    
    if metrics.get('avg_response_time_ms'):
        print(f"Avg Response Time: {metrics['avg_response_time_ms']:.2f}ms")
        print(f"Min Response Time: {metrics['min_response_time_ms']:.2f}ms")
        print(f"Max Response Time: {metrics['max_response_time_ms']:.2f}ms")
    
    # Save results if requested
    if output:
        import json
        with open(output, 'w') as f:
            json.dump(metrics, f, indent=2)
        _print_success(f"Results saved to: {output}")


@cli.command()
@click.argument('test_file', type=click.Path(exists=True))
def add_test(test_file):
    """
    Add a custom test module.
    
    Copy a test file to the custom tests directory where it will be
    automatically discovered and run.
    """
    import shutil
    
    source = Path(test_file)
    dest_dir = Path(__file__).parent / "tests" / "custom"
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    dest = dest_dir / source.name
    
    try:
        shutil.copy(source, dest)
        _print_success(f"Added custom test: {dest}")
        _print_info("Test will be auto-discovered on next run")
    except Exception as e:
        _print_error(f"Failed to add test: {e}")
        sys.exit(1)


@cli.command()
def generate_schema():
    """
    Generate or update Pydantic models from MCP schema.
    
    Downloads the official MCP JSON schema and generates type-safe
    Pydantic models for request/response validation.
    """
    _print_header("Schema Generation")
    
    try:
        from .schemas import generate
        generate.main()
    except Exception as e:
        _print_error(f"Failed to generate schema: {e}")
        sys.exit(1)


# Helper functions for output
def _print_header(text: str):
    """Print a header."""
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]{text}[/bold cyan]")
    else:
        print(f"\n=== {text} ===")


def _print_section(text: str):
    """Print a section header."""
    if RICH_AVAILABLE:
        console.print(f"\n[bold]{text}[/bold]")
    else:
        print(f"\n{text}")


def _print_info(text: str):
    """Print info message."""
    if RICH_AVAILABLE:
        console.print(f"[dim]{text}[/dim]")
    else:
        print(text)


def _print_success(text: str):
    """Print success message."""
    if RICH_AVAILABLE:
        console.print(f"[green]✅ {text}[/green]")
    else:
        print(f"✓ {text}")


def _print_warning(text: str):
    """Print warning message."""
    if RICH_AVAILABLE:
        console.print(f"[yellow]⚠️  {text}[/yellow]")
    else:
        print(f"Warning: {text}")


def _print_error(text: str):
    """Print error message."""
    if RICH_AVAILABLE:
        console.print(f"[red]❌ {text}[/red]")
    else:
        print(f"Error: {text}")


def _display_endpoint_summary(suite):
    """Display summary for an endpoint."""
    if RICH_AVAILABLE:
        # Create summary table
        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Compliance Score", f"{suite.compliance_score:.1f}%")
        table.add_row("Total Tests", str(suite.total_tests))
        table.add_row("Passed", f"[green]{suite.passed}[/green]")
        table.add_row("Failed", f"[red]{suite.failed}[/red]")
        
        if suite.warnings > 0:
            table.add_row("Warnings", f"[yellow]{suite.warnings}[/yellow]")
        if suite.skipped > 0:
            table.add_row("Skipped", str(suite.skipped))
        
        console.print(table)
        
        # Show critical failures
        critical = suite.get_critical_failures()
        if critical:
            console.print("\n[bold red]Critical Failures:[/bold red]")
            for result in critical[:3]:
                console.print(f"  • {result.test_id}: {result.test_name}")
    else:
        # Simple text output
        print(f"\nCompliance Score: {suite.compliance_score:.1f}%")
        print(f"Passed: {suite.passed}/{suite.total_tests}")
        print(f"Failed: {suite.failed}")
        
        critical = suite.get_critical_failures()
        if critical:
            print("\nCritical Failures:")
            for result in critical[:3]:
                print(f"  - {result.test_id}: {result.test_name}")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()