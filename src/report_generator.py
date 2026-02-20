"""
Report Generator - PDF and Markdown export for Sentinel Code
Creates professional security audit reports
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from io import BytesIO

# PDF imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, ListFlowable, ListItem, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

# Markdown import
import markdown


class ReportGenerator:
    """
    Generate professional security audit reports.
    
    Formats:
    - PDF: Full professional report with styling
    - Markdown: Text-based report for GitHub/docs
    - JSON: Structured data for integrations
    """
    
    def __init__(self):
        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)
    
    # =========================================================================
    # MARKDOWN REPORT
    # =========================================================================
    
    def generate_markdown(self, result: Dict, include_fixes: bool = True) -> str:
        """Generate Markdown report from scan result"""
        
        repo = result.get('repo', 'Unknown Repository')
        is_solana = result.get('is_solana_project', False)
        framework = result.get('framework', 'N/A')
        score = result.get('score', 0)
        scan_type = result.get('scan_type', 'general')
        
        critical = result.get('critical', [])
        warnings = result.get('warnings', [])
        improvements = result.get('improvements', [])
        
        # Build report
        lines = []
        
        # Header
        lines.append("# 🛡️ Sentinel Code Security Report")
        lines.append("")
        lines.append(f"**Repository:** {repo}")
        lines.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Scan Type:** {scan_type.upper()}")
        if is_solana:
            lines.append(f"**Framework:** {framework or 'Native Solana'}")
        lines.append("")
        
        # Score
        score_emoji = self._get_score_emoji(score)
        lines.append(f"## Security Score: {score}/100 {score_emoji}")
        lines.append("")
        lines.append(self._get_score_description(score))
        lines.append("")
        
        # Summary stats
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Category | Count |")
        lines.append(f"|----------|-------|")
        lines.append(f"| 🔴 Critical Issues | {len(critical)} |")
        lines.append(f"| 🟡 Warnings | {len(warnings)} |")
        lines.append(f"| 🔵 Improvements | {len(improvements)} |")
        lines.append(f"| Files Analyzed | {result.get('files_analyzed', 'N/A')} |")
        lines.append(f"| Total Lines | {result.get('total_lines', 'N/A')} |")
        lines.append("")
        
        # Languages
        languages = result.get('languages', {})
        if languages:
            lines.append("### Languages")
            lines.append("")
            for lang, pct in languages.items():
                lines.append(f"- {lang}: {pct}%")
            lines.append("")
        
        # Critical Issues
        if critical:
            lines.append("---")
            lines.append("")
            lines.append("## 🔴 Critical Issues")
            lines.append("")
            lines.append("These issues must be fixed before production deployment.")
            lines.append("")
            
            for i, issue in enumerate(critical, 1):
                lines.append(f"### {i}. {issue.get('title', 'Unknown Issue')}")
                lines.append("")
                lines.append(f"**ID:** `{issue.get('id', 'N/A')}`")
                lines.append(f"**File:** `{issue.get('file', 'N/A')}`")
                lines.append(f"**Line:** {issue.get('line', 'N/A')}")
                lines.append("")
                
                lines.append("**Vulnerable Code:**")
                lines.append("```rust")
                lines.append(issue.get('code', 'N/A'))
                lines.append("```")
                lines.append("")
                
                lines.append(f"**Risk:** {issue.get('risk', 'N/A')}")
                lines.append("")
                
                if include_fixes:
                    lines.append(f"**Fix:** {issue.get('fix', 'N/A')}")
                    lines.append("")
                    if issue.get('fix_code'):
                        lines.append("**Fixed Code:**")
                        lines.append("```rust")
                        lines.append(issue.get('fix_code', ''))
                        lines.append("```")
                        lines.append("")
                
                lines.append("")
        
        # Warnings
        if warnings:
            lines.append("---")
            lines.append("")
            lines.append("## 🟡 Warnings")
            lines.append("")
            lines.append("These issues should be addressed to improve security.")
            lines.append("")
            
            for i, warning in enumerate(warnings, 1):
                lines.append(f"### {i}. {warning.get('title', 'Unknown Warning')}")
                lines.append("")
                lines.append(f"**ID:** `{warning.get('id', 'N/A')}`")
                lines.append(f"**File:** `{warning.get('file', 'N/A')}`")
                lines.append(f"**Line:** {warning.get('line', 'N/A')}")
                lines.append("")
                
                if warning.get('code'):
                    lines.append("**Code:**")
                    lines.append("```rust")
                    lines.append(warning.get('code', ''))
                    lines.append("```")
                    lines.append("")
                
                lines.append(f"**Issue:** {warning.get('issue', 'N/A')}")
                lines.append("")
                
                if include_fixes and warning.get('fix'):
                    lines.append(f"**Fix:** {warning.get('fix', 'N/A')}")
                    lines.append("")
                    if warning.get('fix_code'):
                        lines.append("**Fixed Code:**")
                        lines.append("```rust")
                        lines.append(warning.get('fix_code', ''))
                        lines.append("```")
                        lines.append("")
                
                lines.append("")
        
        # Improvements
        if improvements:
            lines.append("---")
            lines.append("")
            lines.append("## 🔵 Improvements")
            lines.append("")
            lines.append("Best practice suggestions to enhance code quality.")
            lines.append("")
            
            for i, imp in enumerate(improvements, 1):
                lines.append(f"### {i}. {imp.get('title', 'Unknown Improvement')}")
                lines.append("")
                lines.append(f"**ID:** `{imp.get('id', 'N/A')}`")
                lines.append(f"**File:** `{imp.get('file', 'N/A')}`")
                lines.append(f"**Line:** {imp.get('line', 'N/A')}")
                lines.append("")
                
                if imp.get('current'):
                    lines.append("**Current:**")
                    lines.append("```rust")
                    lines.append(imp.get('current', ''))
                    lines.append("```")
                    lines.append("")
                
                if imp.get('suggested'):
                    lines.append("**Suggested:**")
                    lines.append("```rust")
                    lines.append(imp.get('suggested', ''))
                    lines.append("```")
                    lines.append("")
                
                if imp.get('benefit'):
                    lines.append(f"**Benefit:** {imp.get('benefit', '')}")
                    lines.append("")
                
                lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append("## About This Report")
        lines.append("")
        lines.append("This security report was generated by **Sentinel Code**, part of the Oracle Sentinel Intelligence Layer.")
        lines.append("")
        lines.append("- Website: [oraclesentinel.xyz](https://oraclesentinel.xyz)")
        lines.append("- Twitter: [@oracle_sentinel](https://x.com/oracle_sentinel)")
        lines.append("")
        if is_solana:
            lines.append("### Solana Vulnerability Reference")
            lines.append("")
            lines.append("- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)")
            lines.append("- [Anchor Documentation](https://www.anchor-lang.com/)")
            lines.append("- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)")
            lines.append("")
        
        lines.append(f"*Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        
        return "\n".join(lines)
    
    def save_markdown(self, result: Dict, filename: str = None) -> str:
        """Save Markdown report to file"""
        if not filename:
            repo_name = result.get('repo', 'unknown').split('/')[-1]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{repo_name}_{timestamp}.md"
        
        filepath = os.path.join(self.reports_dir, filename)
        content = self.generate_markdown(result)
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        return filepath
    
    # =========================================================================
    # PDF REPORT
    # =========================================================================
    
    def generate_pdf(self, result: Dict, include_fixes: bool = True) -> BytesIO:
        """Generate PDF report from scan result"""
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=20*mm,
            leftMargin=20*mm,
            topMargin=20*mm,
            bottomMargin=20*mm
        )
        
        # Styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a2e'),
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#16213e')
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#0f3460')
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            alignment=TA_JUSTIFY
        )
        
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Code'],
            fontSize=8,
            fontName='Courier',
            backColor=colors.HexColor('#f5f5f5'),
            borderPadding=5,
            spaceAfter=10
        )
        
        # Build story
        story = []
        
        repo = result.get('repo', 'Unknown Repository')
        is_solana = result.get('is_solana_project', False)
        framework = result.get('framework', 'N/A')
        score = result.get('score', 0)
        
        critical = result.get('critical', [])
        warnings = result.get('warnings', [])
        improvements = result.get('improvements', [])
        
        # Title
        story.append(Paragraph("🛡️ Sentinel Code", title_style))
        story.append(Paragraph("Security Analysis Report", styles['Heading2']))
        story.append(Spacer(1, 20))
        
        # Metadata table
        meta_data = [
            ['Repository', repo],
            ['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Project Type', 'Solana/Anchor' if is_solana else 'General'],
        ]
        if is_solana and framework:
            meta_data.append(['Framework', framework.capitalize()])
        
        meta_table = Table(meta_data, colWidths=[100, 350])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8e8e8')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))
        
        # Score section
        score_color = self._get_score_color(score)
        story.append(Paragraph(f"Security Score: {score}/100", heading_style))
        
        # Score bar
        score_data = [[f'{score}/100']]
        score_table = Table(score_data, colWidths=[score * 4.5])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), score_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(score_table)
        story.append(Paragraph(self._get_score_description(score), body_style))
        story.append(Spacer(1, 15))
        
        # Summary table
        story.append(Paragraph("Summary", heading_style))
        summary_data = [
            ['Category', 'Count'],
            ['🔴 Critical Issues', str(len(critical))],
            ['🟡 Warnings', str(len(warnings))],
            ['🔵 Improvements', str(len(improvements))],
            ['Files Analyzed', str(result.get('files_analyzed', 'N/A'))],
            ['Total Lines', str(result.get('total_lines', 'N/A'))],
        ]
        summary_table = Table(summary_data, colWidths=[200, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Critical Issues
        if critical:
            story.append(PageBreak())
            story.append(Paragraph("🔴 Critical Issues", heading_style))
            story.append(Paragraph(
                "These security vulnerabilities must be fixed before production deployment.",
                body_style
            ))
            story.append(Spacer(1, 10))
            
            for i, issue in enumerate(critical, 1):
                story.append(Paragraph(
                    f"{i}. {issue.get('title', 'Unknown Issue')} ({issue.get('id', 'N/A')})",
                    subheading_style
                ))
                story.append(Paragraph(
                    f"<b>File:</b> {issue.get('file', 'N/A')} | <b>Line:</b> {issue.get('line', 'N/A')}",
                    body_style
                ))
                story.append(Paragraph(f"<b>Risk:</b> {issue.get('risk', 'N/A')}", body_style))
                
                if issue.get('code'):
                    story.append(Paragraph("<b>Vulnerable Code:</b>", body_style))
                    # Escape special characters for code
                    code_text = issue.get('code', '').replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(f"<font face='Courier' size='8'>{code_text}</font>", code_style))
                
                if include_fixes and issue.get('fix'):
                    story.append(Paragraph(f"<b>Fix:</b> {issue.get('fix', 'N/A')}", body_style))
                    if issue.get('fix_code'):
                        story.append(Paragraph("<b>Fixed Code:</b>", body_style))
                        fix_code = issue.get('fix_code', '').replace('<', '&lt;').replace('>', '&gt;')
                        story.append(Paragraph(f"<font face='Courier' size='8'>{fix_code}</font>", code_style))
                
                story.append(Spacer(1, 15))
        
        # Warnings (abbreviated)
        if warnings:
            story.append(PageBreak())
            story.append(Paragraph("🟡 Warnings", heading_style))
            story.append(Paragraph(
                f"Found {len(warnings)} warning(s) that should be addressed.",
                body_style
            ))
            story.append(Spacer(1, 10))
            
            for i, warning in enumerate(warnings[:10], 1):  # Limit to first 10
                story.append(Paragraph(
                    f"{i}. {warning.get('title', 'Unknown')} - {warning.get('file', 'N/A')}:{warning.get('line', 'N/A')}",
                    body_style
                ))
            
            if len(warnings) > 10:
                story.append(Paragraph(
                    f"... and {len(warnings) - 10} more warnings. See full report for details.",
                    body_style
                ))
        
        # Improvements (abbreviated)
        if improvements:
            story.append(Spacer(1, 20))
            story.append(Paragraph("🔵 Improvements", heading_style))
            story.append(Paragraph(
                f"Found {len(improvements)} improvement suggestion(s).",
                body_style
            ))
            story.append(Spacer(1, 10))
            
            for i, imp in enumerate(improvements[:10], 1):
                story.append(Paragraph(
                    f"{i}. {imp.get('title', 'Unknown')} - {imp.get('file', 'N/A')}:{imp.get('line', 'N/A')}",
                    body_style
                ))
            
            if len(improvements) > 10:
                story.append(Paragraph(
                    f"... and {len(improvements) - 10} more suggestions.",
                    body_style
                ))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", color=colors.grey))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "Generated by <b>Sentinel Code</b> - Part of Oracle Sentinel Intelligence Layer",
            ParagraphStyle('Footer', parent=body_style, fontSize=8, textColor=colors.grey)
        ))
        story.append(Paragraph(
            "https://oraclesentinel.xyz | @oracle_sentinel",
            ParagraphStyle('Footer', parent=body_style, fontSize=8, textColor=colors.grey)
        ))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return buffer
    
    def save_pdf(self, result: Dict, filename: str = None) -> str:
        """Save PDF report to file"""
        if not filename:
            repo_name = result.get('repo', 'unknown').split('/')[-1]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{repo_name}_{timestamp}.pdf"
        
        filepath = os.path.join(self.reports_dir, filename)
        pdf_buffer = self.generate_pdf(result)
        
        with open(filepath, 'wb') as f:
            f.write(pdf_buffer.read())
        
        return filepath
    
    # =========================================================================
    # COMPARISON REPORT
    # =========================================================================
    
    def generate_comparison_markdown(self, comparison: Dict) -> str:
        """Generate Markdown report comparing two scans"""
        
        old_scan = comparison.get('old_scan', {})
        new_scan = comparison.get('new_scan', {})
        comp = comparison.get('comparison', {})
        
        lines = []
        
        lines.append("# 📊 Sentinel Code - Scan Comparison Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        # Score comparison
        score_change = comp.get('score_change', 0)
        if score_change > 0:
            score_indicator = f"📈 +{score_change}"
        elif score_change < 0:
            score_indicator = f"📉 {score_change}"
        else:
            score_indicator = "➡️ 0"
        
        lines.append("## Score Change")
        lines.append("")
        lines.append(f"| Metric | Previous | Current | Change |")
        lines.append(f"|--------|----------|---------|--------|")
        lines.append(f"| Score | {old_scan.get('score', 0)} | {new_scan.get('score', 0)} | {score_indicator} |")
        lines.append(f"| Critical | {old_scan.get('critical_count', 0)} | {new_scan.get('critical_count', 0)} | {new_scan.get('critical_count', 0) - old_scan.get('critical_count', 0):+d} |")
        lines.append(f"| Warnings | {old_scan.get('warning_count', 0)} | {new_scan.get('warning_count', 0)} | {new_scan.get('warning_count', 0) - old_scan.get('warning_count', 0):+d} |")
        lines.append("")
        
        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(comparison.get('summary', 'No summary available.'))
        lines.append("")
        
        # Fixed issues
        if comp.get('fixed_critical', 0) > 0 or comp.get('fixed_warnings', 0) > 0:
            lines.append("## ✅ Fixed Issues")
            lines.append("")
            if comp.get('fixed_critical', 0) > 0:
                lines.append(f"**Critical issues fixed:** {comp.get('fixed_critical', 0)}")
                for sig in comp.get('fixed_critical_list', []):
                    lines.append(f"- `{sig}`")
                lines.append("")
            if comp.get('fixed_warnings', 0) > 0:
                lines.append(f"**Warnings fixed:** {comp.get('fixed_warnings', 0)}")
                for sig in comp.get('fixed_warnings_list', []):
                    lines.append(f"- `{sig}`")
                lines.append("")
        
        # New issues
        if comp.get('new_critical', 0) > 0 or comp.get('new_warnings', 0) > 0:
            lines.append("## ⚠️ New Issues")
            lines.append("")
            if comp.get('new_critical', 0) > 0:
                lines.append(f"**New critical issues:** {comp.get('new_critical', 0)}")
                for sig in comp.get('new_critical_list', []):
                    lines.append(f"- `{sig}`")
                lines.append("")
            if comp.get('new_warnings', 0) > 0:
                lines.append(f"**New warnings:** {comp.get('new_warnings', 0)}")
                for sig in comp.get('new_warnings_list', []):
                    lines.append(f"- `{sig}`")
                lines.append("")
        
        # Scan details
        lines.append("## Scan Details")
        lines.append("")
        lines.append(f"- **Previous scan:** ID #{old_scan.get('id')} at {old_scan.get('scanned_at')}")
        lines.append(f"- **Current scan:** ID #{new_scan.get('id')} at {new_scan.get('scanned_at')}")
        lines.append("")
        
        lines.append("---")
        lines.append("*Generated by Sentinel Code - Oracle Sentinel Intelligence Layer*")
        
        return "\n".join(lines)
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _get_score_emoji(self, score: int) -> str:
        """Get emoji based on score"""
        if score >= 80:
            return "🟢"
        elif score >= 60:
            return "🟡"
        elif score >= 40:
            return "🟠"
        else:
            return "🔴"
    
    def _get_score_color(self, score: int) -> colors.Color:
        """Get color based on score"""
        if score >= 80:
            return colors.HexColor('#27ae60')  # Green
        elif score >= 60:
            return colors.HexColor('#f39c12')  # Yellow
        elif score >= 40:
            return colors.HexColor('#e67e22')  # Orange
        else:
            return colors.HexColor('#e74c3c')  # Red
    
    def _get_score_description(self, score: int) -> str:
        """Get description based on score"""
        if score >= 80:
            return "Excellent! This codebase follows security best practices with minimal issues."
        elif score >= 60:
            return "Good security posture with some areas for improvement."
        elif score >= 40:
            return "Moderate security concerns that should be addressed before production."
        else:
            return "Critical security issues detected. Immediate attention required."


# Singleton instance
report_generator = ReportGenerator()
