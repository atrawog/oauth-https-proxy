"""
YAML report generator for MCP compliance testing.

Generates comprehensive, verbose YAML reports that include:
- Detailed test results with explanations
- Failure reasons and impact assessments
- Step-by-step remediation guidance
- Evidence and metrics
- Compliance scores and recommendations
"""

import yaml
from datetime import datetime
from typing import List, Dict, Any, Optional, TextIO
from pathlib import Path
import logging

from ..models.test_results import TestResult, TestSuite, TestStatus
from ..core.registry import TestCategory


logger = logging.getLogger(__name__)


class YAMLReporter:
    """
    Generate comprehensive YAML reports with verbose explanations.
    
    The reports are designed to be:
    - Educational: Explain what each test does and why it matters
    - Actionable: Provide clear remediation steps
    - Evidence-based: Include actual requests/responses
    - Prioritized: Highlight critical issues
    """
    
    def __init__(self, include_passing: bool = False, include_evidence: bool = True):
        """
        Initialize YAML reporter.
        
        Args:
            include_passing: Include passing tests in report
            include_evidence: Include evidence (requests/responses) in report
        """
        self.include_passing = include_passing
        self.include_evidence = include_evidence
    
    def generate_report(self,
                       suite: TestSuite,
                       output_path: Optional[str] = None,
                       output_file: Optional[TextIO] = None) -> Dict[str, Any]:
        """
        Generate comprehensive YAML compliance report.
        
        Args:
            suite: Test suite with results
            output_path: Optional file path to write to
            output_file: Optional file object to write to
        
        Returns:
            Report dictionary
        """
        logger.info(f"Generating YAML report for {len(suite.results)} test results")
        
        # Build report structure
        report = {
            'metadata': self._generate_metadata(suite),
            'summary': self._generate_summary(suite),
            'compliance_assessment': self._generate_compliance_assessment(suite),
            'test_results': self._organize_results(suite.results),
            'critical_failures': self._extract_critical_failures(suite),
            'recommendations': self._generate_recommendations(suite),
            'compliance_matrix': self._generate_compliance_matrix(suite),
            'implementation_roadmap': self._generate_roadmap(suite)
        }
        
        # Write to file if path provided
        if output_path:
            self._write_yaml_file(report, output_path)
            logger.info(f"Report written to: {output_path}")
        
        # Write to file object if provided
        if output_file:
            yaml.dump(report, output_file, **self._get_yaml_options())
        
        return report
    
    def _generate_metadata(self, suite: TestSuite) -> Dict[str, Any]:
        """Generate report metadata section."""
        duration = 0.0
        if suite.completed_at and suite.started_at:
            duration = (suite.completed_at - suite.started_at).total_seconds()
        
        return {
            'report_version': '1.0.0',
            'mcp_specification_version': '2025-06-18',
            'verification_tool_version': '1.0.0',
            'report_id': suite.suite_id,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'endpoint_tested': suite.endpoint,
            'test_started_at': suite.started_at.isoformat() + 'Z',
            'test_completed_at': suite.completed_at.isoformat() + 'Z' if suite.completed_at else None,
            'test_duration_seconds': round(duration, 2),
            'total_tests_run': suite.total_tests,
            'environment': {
                'platform': 'MCP Verification Tools',
                'protocol_version': '2025-06-18'
            }
        }
    
    def _generate_summary(self, suite: TestSuite) -> Dict[str, Any]:
        """Generate summary statistics."""
        # Calculate category breakdowns
        categories = {}
        for result in suite.results:
            cat = result.category
            if cat not in categories:
                categories[cat] = {'passed': 0, 'failed': 0, 'total': 0}
            
            categories[cat]['total'] += 1
            if result.status == TestStatus.PASSED:
                categories[cat]['passed'] += 1
            elif result.status in [TestStatus.FAILED, TestStatus.ERROR]:
                categories[cat]['failed'] += 1
        
        # Calculate scores
        for cat, stats in categories.items():
            if stats['total'] > 0:
                stats['score'] = round((stats['passed'] / stats['total']) * 100, 1)
            else:
                stats['score'] = 0.0
        
        return {
            'compliance_score': round(suite.compliance_score, 1),
            'status': self._determine_compliance_status(suite.compliance_score),
            'passed_tests': suite.passed,
            'failed_tests': suite.failed,
            'warning_tests': suite.warnings,
            'skipped_tests': suite.skipped,
            'error_tests': suite.errors,
            'categories': categories
        }
    
    def _determine_compliance_status(self, score: float) -> str:
        """Determine compliance status based on score."""
        if score >= 95:
            return "FULLY_COMPLIANT"
        elif score >= 80:
            return "MOSTLY_COMPLIANT"
        elif score >= 60:
            return "PARTIALLY_COMPLIANT"
        elif score >= 40:
            return "LIMITED_COMPLIANCE"
        else:
            return "NON_COMPLIANT"
    
    def _generate_compliance_assessment(self, suite: TestSuite) -> Dict[str, Any]:
        """Generate overall compliance assessment."""
        critical_count = len([
            r for r in suite.results 
            if r.status == TestStatus.FAILED and r.severity == "CRITICAL"
        ])
        
        high_count = len([
            r for r in suite.results 
            if r.status == TestStatus.FAILED and r.severity == "HIGH"
        ])
        
        assessment = {
            'overall_verdict': self._get_verdict(suite),
            'compliance_percentage': round(suite.compliance_score, 1),
            'critical_issues': critical_count,
            'high_priority_issues': high_count,
            'production_ready': critical_count == 0 and suite.compliance_score >= 80,
            'security_posture': self._assess_security(suite),
            'performance_rating': self._assess_performance(suite),
            'spec_coverage': self._calculate_spec_coverage(suite)
        }
        
        return assessment
    
    def _get_verdict(self, suite: TestSuite) -> str:
        """Get overall verdict for the endpoint."""
        if suite.compliance_score >= 95:
            return "✅ EXCELLENT - Endpoint is fully compliant with MCP specification"
        elif suite.compliance_score >= 80:
            return "👍 GOOD - Endpoint is mostly compliant with minor issues"
        elif suite.compliance_score >= 60:
            return "⚠️ FAIR - Endpoint has significant compliance gaps"
        else:
            return "❌ POOR - Endpoint has critical compliance failures"
    
    def _assess_security(self, suite: TestSuite) -> str:
        """Assess security posture based on security test results."""
        security_results = [
            r for r in suite.results 
            if r.category == TestCategory.SECURITY.value
        ]
        
        if not security_results:
            return "NOT_TESTED"
        
        failed_security = [
            r for r in security_results 
            if r.status == TestStatus.FAILED
        ]
        
        if not failed_security:
            return "SECURE"
        elif any(r.severity == "CRITICAL" for r in failed_security):
            return "CRITICAL_VULNERABILITIES"
        elif any(r.severity == "HIGH" for r in failed_security):
            return "HIGH_RISK"
        else:
            return "MODERATE_RISK"
    
    def _assess_performance(self, suite: TestSuite) -> str:
        """Assess performance based on performance test results."""
        perf_results = [
            r for r in suite.results 
            if r.category == TestCategory.PERFORMANCE.value
        ]
        
        if not perf_results:
            return "NOT_TESTED"
        
        # Check metrics
        avg_response_times = []
        for r in perf_results:
            if r.metrics and r.metrics.response_time_ms:
                avg_response_times.append(r.metrics.response_time_ms)
        
        if avg_response_times:
            avg_time = sum(avg_response_times) / len(avg_response_times)
            if avg_time < 100:
                return "EXCELLENT"
            elif avg_time < 500:
                return "GOOD"
            elif avg_time < 1000:
                return "ACCEPTABLE"
            else:
                return "POOR"
        
        return "UNKNOWN"
    
    def _calculate_spec_coverage(self, suite: TestSuite) -> Dict[str, float]:
        """Calculate specification coverage by category."""
        # Define expected test counts per category (approximate)
        expected_counts = {
            TestCategory.SESSION.value: 10,
            TestCategory.TRANSPORT.value: 8,
            TestCategory.PROTOCOL.value: 12,
            TestCategory.TOOLS.value: 8,
            TestCategory.SECURITY.value: 6,
            TestCategory.PERFORMANCE.value: 5,
            TestCategory.RESOURCES.value: 4,
            TestCategory.PROMPTS.value: 4
        }
        
        coverage = {}
        for cat, expected in expected_counts.items():
            actual = len([r for r in suite.results if r.category == cat])
            coverage[cat] = min(100.0, round((actual / expected) * 100, 1))
        
        return coverage
    
    def _organize_results(self, results: List[TestResult]) -> Dict[str, List[Dict]]:
        """
        Organize results by category with detailed explanations.
        
        Args:
            results: List of test results
        
        Returns:
            Dictionary organized by category
        """
        organized = {}
        
        for result in results:
            # Skip passing tests if not requested
            if result.status == TestStatus.PASSED and not self.include_passing:
                continue
            
            category = result.category
            if category not in organized:
                organized[category] = []
            
            # Build comprehensive test entry
            test_entry = self._build_test_entry(result)
            organized[category].append(test_entry)
        
        return organized
    
    def _build_test_entry(self, result: TestResult) -> Dict[str, Any]:
        """Build a comprehensive test entry for the report."""
        entry = {
            'test_id': result.test_id,
            'test_name': result.test_name,
            'status': result.status.value,
            'severity': result.severity
        }
        
        # Add descriptions
        if result.description:
            entry['description'] = self._format_multiline(result.description)
        
        if result.spec_reference:
            entry['specification_reference'] = result.spec_reference
        
        if result.methodology:
            entry['test_methodology'] = self._format_multiline(result.methodology)
        
        # Add expected vs actual
        if result.expected_behavior:
            entry['expected_behavior'] = self._format_multiline(result.expected_behavior)
        
        if result.actual_behavior:
            entry['actual_behavior'] = self._format_multiline(result.actual_behavior)
        
        # Add failure details if applicable
        if result.status in [TestStatus.FAILED, TestStatus.ERROR]:
            if result.failure_reason:
                entry['failure_reason'] = self._format_multiline(result.failure_reason)
            
            if result.impact_assessment:
                entry['impact_assessment'] = result.impact_assessment.model_dump()
            
            if result.remediation:
                entry['remediation'] = result.remediation.model_dump()
        
        # Add evidence if requested and available
        if self.include_evidence and result.evidence:
            entry['evidence'] = result.evidence.model_dump(exclude_none=True)
        
        # Add metrics if available
        if result.metrics:
            entry['performance_metrics'] = result.metrics.model_dump(exclude_none=True)
        
        # Add timing
        if result.duration_seconds:
            entry['execution_time_seconds'] = round(result.duration_seconds, 3)
        
        return entry
    
    def _extract_critical_failures(self, suite: TestSuite) -> List[Dict[str, Any]]:
        """Extract critical failures that need immediate attention."""
        critical = []
        
        for result in suite.results:
            if result.status == TestStatus.FAILED and result.severity == "CRITICAL":
                critical.append({
                    'test_id': result.test_id,
                    'test_name': result.test_name,
                    'category': result.category,
                    'failure_summary': self._summarize_failure(result),
                    'immediate_action_required': self._get_immediate_action(result)
                })
        
        return critical
    
    def _summarize_failure(self, result: TestResult) -> str:
        """Create a concise summary of a failure."""
        if result.failure_reason:
            # Take first paragraph or first 200 chars
            lines = result.failure_reason.strip().split('\n')
            if lines:
                summary = lines[0].strip()
                if len(summary) > 200:
                    summary = summary[:197] + "..."
                return summary
        return "Test failed without specific reason"
    
    def _get_immediate_action(self, result: TestResult) -> str:
        """Get the most important immediate action for a failure."""
        if result.remediation and result.remediation.steps:
            return result.remediation.steps[0]
        
        # Default actions based on category
        defaults = {
            TestCategory.SECURITY.value: "Review and fix security vulnerability immediately",
            TestCategory.SESSION.value: "Fix session management implementation",
            TestCategory.PROTOCOL.value: "Ensure JSON-RPC compliance",
            TestCategory.TRANSPORT.value: "Fix HTTP transport implementation"
        }
        
        return defaults.get(result.category, "Review and fix the failing test")
    
    def _generate_recommendations(self, suite: TestSuite) -> Dict[str, List[str]]:
        """Generate prioritized recommendations."""
        recommendations = {
            'critical_fixes': [],
            'high_priority': [],
            'medium_priority': [],
            'improvements': [],
            'best_practices': []
        }
        
        # Analyze failures and generate recommendations
        for result in suite.results:
            if result.status != TestStatus.FAILED:
                continue
            
            if result.remediation and result.remediation.steps:
                priority = result.remediation.priority
                steps = result.remediation.steps
                
                if priority == "IMMEDIATE" or result.severity == "CRITICAL":
                    recommendations['critical_fixes'].extend(steps[:2])
                elif priority == "HIGH" or result.severity == "HIGH":
                    recommendations['high_priority'].extend(steps[:2])
                elif priority == "MEDIUM":
                    recommendations['medium_priority'].extend(steps[:1])
        
        # Add general recommendations
        if suite.compliance_score < 80:
            recommendations['improvements'].append(
                "Focus on achieving at least 80% compliance before production deployment"
            )
        
        # Security recommendations
        security_failures = [
            r for r in suite.results
            if r.category == TestCategory.SECURITY.value and r.status == TestStatus.FAILED
        ]
        if security_failures:
            recommendations['best_practices'].append(
                "Implement comprehensive security testing in your CI/CD pipeline"
            )
            recommendations['best_practices'].append(
                "Consider security audit before production deployment"
            )
        
        # Remove duplicates while preserving order
        for key in recommendations:
            recommendations[key] = list(dict.fromkeys(recommendations[key]))
        
        return recommendations
    
    def _generate_compliance_matrix(self, suite: TestSuite) -> Dict[str, Dict[str, Any]]:
        """Generate a compliance matrix showing spec coverage."""
        matrix = {}
        
        # Group by category
        for category in TestCategory:
            cat_results = [
                r for r in suite.results 
                if r.category == category.value
            ]
            
            if not cat_results:
                continue
            
            passed = len([r for r in cat_results if r.status == TestStatus.PASSED])
            failed = len([r for r in cat_results if r.status == TestStatus.FAILED])
            total = len(cat_results)
            
            matrix[category.value] = {
                'total_tests': total,
                'passed': passed,
                'failed': failed,
                'compliance_percentage': round((passed / total * 100) if total > 0 else 0, 1),
                'status': 'COMPLIANT' if failed == 0 else 'NON_COMPLIANT'
            }
        
        return matrix
    
    def _generate_roadmap(self, suite: TestSuite) -> List[Dict[str, Any]]:
        """Generate implementation roadmap based on failures."""
        roadmap = []
        
        # Phase 1: Critical fixes
        critical_failures = [
            r for r in suite.results
            if r.status == TestStatus.FAILED and r.severity == "CRITICAL"
        ]
        if critical_failures:
            roadmap.append({
                'phase': 1,
                'name': 'Critical Compliance Fixes',
                'priority': 'IMMEDIATE',
                'duration_estimate': '1-2 days',
                'tasks': [
                    f"Fix {r.test_id}: {r.test_name}" 
                    for r in critical_failures[:5]
                ]
            })
        
        # Phase 2: High priority fixes
        high_failures = [
            r for r in suite.results
            if r.status == TestStatus.FAILED and r.severity == "HIGH"
        ]
        if high_failures:
            roadmap.append({
                'phase': 2,
                'name': 'High Priority Improvements',
                'priority': 'HIGH',
                'duration_estimate': '3-5 days',
                'tasks': [
                    f"Fix {r.test_id}: {r.test_name}" 
                    for r in high_failures[:5]
                ]
            })
        
        # Phase 3: Full compliance
        if suite.compliance_score < 95:
            roadmap.append({
                'phase': 3,
                'name': 'Full Compliance Achievement',
                'priority': 'MEDIUM',
                'duration_estimate': '1-2 weeks',
                'tasks': [
                    'Address all remaining test failures',
                    'Implement missing optional features',
                    'Optimize performance metrics',
                    'Complete security hardening'
                ]
            })
        
        return roadmap
    
    def _format_multiline(self, text: str) -> str:
        """Format multiline text for clean YAML output."""
        if not text:
            return ""
        
        # Remove excessive whitespace while preserving structure
        lines = text.strip().split('\n')
        cleaned = []
        for line in lines:
            # Preserve indentation but remove trailing spaces
            cleaned.append(line.rstrip())
        
        return '\n'.join(cleaned)
    
    def _get_yaml_options(self) -> Dict[str, Any]:
        """Get YAML dump options for consistent output."""
        return {
            'default_flow_style': False,
            'sort_keys': False,
            'allow_unicode': True,
            'width': 100,
            'indent': 2
        }
    
    def _write_yaml_file(self, report: Dict[str, Any], output_path: str):
        """Write report to YAML file with proper formatting."""
        # Custom representer for multiline strings
        def str_presenter(dumper, data):
            if '\n' in data and len(data) > 80:
                return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            return dumper.represent_scalar('tag:yaml.org,2002:str', data)
        
        yaml.add_representer(str, str_presenter)
        
        # Write file
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(report, f, **self._get_yaml_options())