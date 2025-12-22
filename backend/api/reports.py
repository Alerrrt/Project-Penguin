from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import FileResponse, StreamingResponse
from typing import Dict, Any, List
import os
import io
from pathlib import Path
from datetime import datetime
from backend.scanner_engine import ScannerEngine
from backend.utils.snapshot_store import load_snapshot
import httpx
from backend.utils.newsletter_store import store_email

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, Drawing
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing, String, Circle, Rect, Line
    from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
    from reportlab.graphics.charts.legends import Legend
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

router = APIRouter()

async def get_scanner_engine(request: Request) -> ScannerEngine:
    engine = getattr(request.app.state, "scanner_engine", None)
    if engine is None:
        raise Exception("Scanner engine not configured")
    return engine

@router.post("/scans/generate_pdf")
async def generate_pdf_report(
    payload: Dict[str, Any],
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Generate and return a dynamic PDF report for a scan."""
    try:
        scan_id = payload.get("scan_id")
        url = payload.get("url")
        
        if not scan_id:
            raise HTTPException(status_code=400, detail="Scan ID is required")
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Get scan results
        scan_data = None
        try:
            scan_data = await engine.get_scan_status(scan_id)
        except Exception:
            pass
        
        # Fallback to snapshot if live data not available
        if not scan_data:
            scan_data = load_snapshot(scan_id)
        
        if not scan_data:
            raise HTTPException(status_code=404, detail=f"Scan results not found for ID: {scan_id}")
        
        # Generate dynamic PDF if reportlab is available
        if REPORTLAB_AVAILABLE:
            pdf_buffer = generate_enhanced_dashboard_pdf(scan_data, url)
            return StreamingResponse(
                io.BytesIO(pdf_buffer.getvalue()),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=project_echo_security_report_{scan_id}.pdf"}
            )
        else:
            # Fallback to static template
            pdf_path = Path("frontend/public/Pdf_Template.pdf")
            if not pdf_path.exists():
                raise HTTPException(status_code=404, detail="PDF template not found")
            
            return FileResponse(
                path=str(pdf_path),
                media_type="application/pdf",
                filename="project_echo_security_report.pdf"
            )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

@router.post("/scans/user_info")
async def save_user_info(payload: Dict[str, Any]):
    """Save user information when downloading reports."""
    try:
        email = payload.get("email")
        url = payload.get("url")
        
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Valid email is required")
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Store the email (you can extend this to store more user info if needed)
        store_email(email)
        
        return {"status": "success", "message": "User information saved"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save user info: {str(e)}")

# Returns a dynamic aggregated report, even if scan was cancelled (partial)
@router.get("/scans/{scan_id}/results", response_model=Dict)
async def get_scan_results(
    scan_id: str,
    engine: ScannerEngine = Depends(get_scanner_engine)
):
    """Get an aggregated report for a scan, including partial results if cancelled."""
    # Try live engine state first
    try:
        scan_data = await engine.get_scan_status(scan_id)
    except Exception:
        scan_data = None

    # Fallback to snapshot when live is missing or cancelled
    snapshot = load_snapshot(scan_id)

    if not scan_data and not snapshot:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    # Choose the freshest source
    report_source: Dict[str, Any] = {}
    if scan_data:
        report_source = scan_data
    elif snapshot:
        report_source = snapshot

    results = report_source.get("results", [])
    status = report_source.get("status", "unknown")
    start_time = report_source.get("start_time") or report_source.get("created_at")
    end_time = report_source.get("end_time") or report_source.get("completed_at")

    # Build a simple summary
    severity_counts: Dict[str, int] = {}
    for f in results:
        sev = (f.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary = {
        "total_findings": len(results),
        "by_severity": severity_counts,
        "scan_duration_seconds": None,
    }
    # Duration if timestamps available
    # Note: Frontend can interpret null if missing

    return {
        "scan_id": report_source.get("id") or scan_id,
        "target": report_source.get("target", ""),
        "scan_type": report_source.get("type") or report_source.get("scan_type"),
        "status": status,
        "results": {
            "findings": results,
            "summary": summary,
        },
        "created_at": start_time,
        "completed_at": end_time,
    }


@router.post("/newsletter/subscribe-and-unlock")
async def subscribe_and_unlock(payload: Dict[str, Any]):
    """Store email and return a token that the frontend can use to unlock report downloads."""
    email = (payload or {}).get("email")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    try:
        store_email(email)
        # Minimal token; frontend just needs ack to show full report/downloads
        return {"status": "ok", "unlocked": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/newsletter/subscribe")
async def subscribe_newsletter(payload: Dict[str, Any]):
    email = (payload or {}).get("email")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    try:
        store_email(email)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _safe_hex(color_hex: str):
    try:
        return colors.HexColor(color_hex)
    except Exception:
        return colors.purple

def generate_enhanced_dashboard_pdf(scan_data: Dict[str, Any], target_url: str) -> io.BytesIO:
    """Generate an enhanced dashboard-style PDF report matching the screenshot layout exactly."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles matching the dark theme from screenshot
    title_style = ParagraphStyle(
        'DashboardTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=20,
        alignment=TA_LEFT,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DashboardSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=10,
        alignment=TA_LEFT,
        textColor=colors.lightblue,
        fontName='Helvetica'
    )
    
    body_style = ParagraphStyle(
        'DashboardBody',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=6,
        alignment=TA_LEFT,
        textColor=colors.white,
        fontName='Helvetica'
    )
    
    # Extract scan data
    findings = scan_data.get("results", [])
    scan_id = scan_data.get("id", "N/A")
    scan_status = scan_data.get("status", "N/A")
    start_time = scan_data.get("start_time")
    end_time = scan_data.get("end_time")
    
    # Calculate severity counts from real data
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    total_findings = sum(severity_counts.values())
    
    # Calculate overall severity percentage (based on weighted severity)
    if total_findings > 0:
        weighted_score = (
            severity_counts["critical"] * 100 +
            severity_counts["high"] * 75 +
            severity_counts["medium"] * 50 +
            severity_counts["low"] * 25 +
            severity_counts["info"] * 10
        ) / total_findings
        overall_severity = min(100, max(0, weighted_score))
    else:
        overall_severity = 0
    
    # Determine risk level from real data
    if overall_severity >= 80:
        risk_level = "CRITICAL"
    elif overall_severity >= 60:
        risk_level = "HIGH"
    elif overall_severity >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # Format timestamps
    report_date = datetime.now().strftime("%a, %d-%m-%Y, %H:%M")
    if start_time:
        try:
            start_dt = datetime.fromtimestamp(start_time) if isinstance(start_time, (int, float)) else start_time
            start_formatted = start_dt.strftime("%a, %d-%m-%Y, %H:%M")
        except:
            start_formatted = "N/A"
    else:
        start_formatted = "N/A"
    
    # Create dashboard layout matching the screenshot exactly
    
    # 1. TOP SECTION - Title and Call to Action Banner
    header_data = [
        ["LATEST SECURITY CHECK REPORT", "Unlock the Full Report Free by Creating an Account"],
        ["", "Get full report details and more testing capacity"]
    ]
    
    header_table = Table(header_data, colWidths=[4*inch, 3*inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), _safe_hex('#0B1F3A')),
        ('BACKGROUND', (1, 0), (1, 1), _safe_hex('#1E293B')),
        ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
        ('TEXTCOLOR', (1, 0), (1, 1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (0, 0), 20),
        ('FONTSIZE', (1, 0), (1, 1), 12),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [_safe_hex('#0B1F3A'), _safe_hex('#1E293B')]),
        ('GRID', (0, 0), (-1, -1), 0.5, _safe_hex('#334155'))
    ]))
    
    story.append(header_table)
    story.append(Spacer(1, 20))
    
    # 2. CENTRAL SECTION - Website Details and Risk Level
    # Try to fetch site preview for favicon/title/image
    site_title = target_url
    site_image_path = None
    try:
      # Use configured backend port if available; keep route compatible with alias
      backend_port = os.environ.get('PORT') or os.environ.get('BACKEND_PORT') or '9000'
      preview_url = f"http://localhost:{backend_port}/api/site_preview?url={target_url}"
      with httpx.Client(timeout=5.0, follow_redirects=True) as client:
          resp = client.get(preview_url)
          if resp.status_code == 200:
              preview = resp.json()
              site_title = preview.get('title') or site_title
              img_url = preview.get('image')
              if img_url:
                  img_resp = client.get(img_url)
                  if img_resp.status_code == 200:
                      tmp = io.BytesIO(img_resp.content)
                      tmp.seek(0)
                      site_image_path = tmp
    except Exception:
      pass
    central_data = [
        ["Website URL:", target_url],
        ["Report Generated:", report_date],
        ["Server Location:", "Chennai"],  # Could be made dynamic
        ["Location:", "Chennai"],         # Could be made dynamic
        ["", ""],  # Empty row for spacing
        ["", ""],  # Empty row for spacing
        ["Risk Level", risk_level]
    ]
    
    central_table = Table(central_data, colWidths=[2*inch, 4*inch])
    central_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), _safe_hex('#0B1F3A')),
        ('BACKGROUND', (1, 0), (1, -2), _safe_hex('#1E293B')),
        ('BACKGROUND', (0, -1), (1, -1), _safe_hex('#7F1D1D')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('TEXTCOLOR', (1, 0), (1, -2), colors.white),
        ('TEXTCOLOR', (0, -1), (1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -2), 'Helvetica'),
        ('FONTNAME', (0, -1), (1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, -1), (1, -1), 24),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, _safe_hex('#334155'))
    ]))
    
    story.append(central_table)
    story.append(Spacer(1, 20))

    # Optional: include preview image block under header when available
    if site_image_path:
        try:
            story.append(Image(site_image_path, width=3.2*inch, height=1.8*inch))
            story.append(Spacer(1, 12))
        except Exception:
            pass
    
    # 3. BOTTOM LEFT - Vulnerabilities Identified (Bar Chart)
    # Create horizontal bar chart for vulnerabilities
    drawing = Drawing(4*inch, 2*inch)
    
    # Create horizontal bar chart
    bc = HorizontalBarChart()
    bc.x = 0
    bc.y = 0
    bc.width = 3.5*inch
    bc.height = 1.5*inch
    # ReportLab expects a sequence of sequences for data
    bc.data = [[
        severity_counts["critical"],
        severity_counts["high"], 
        severity_counts["medium"],
        severity_counts["low"]
    ]]
    bc.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(severity_counts.values()) * 1.2 if max(severity_counts.values()) > 0 else 100
    
    # Set colors matching the screenshot (validated hex)
    from reportlab.lib import colors as _c
    bar_colors = [
        _safe_hex('#7C3AED'),  # critical
        _safe_hex('#8B5CF6'),  # high
        _safe_hex('#A78BFA'),  # medium
        _safe_hex('#C4B5FD'),  # low
    ]
    for i, col in enumerate(bar_colors):
        try:
            bc.bars[i].fillColor = col
        except Exception:
            pass
    
    drawing.add(bc)
    
    # Add title
    title_text = String(2*inch, 1.8*inch, "Vulnerabilities Identified")
    title_text.fontSize = 14
    title_text.fontName = 'Helvetica-Bold'
    title_text.fillColor = colors.white
    drawing.add(title_text)
    
    story.append(drawing)
    
    # 4. BOTTOM RIGHT - Risk Levels (Pie Chart)
    # Create pie chart for risk levels
    pie_drawing = Drawing(3*inch, 2.2*inch)

    # Calculate percentages for pie chart
    if total_findings > 0:
        critical_pct = (severity_counts["critical"] / total_findings) * 100
        high_pct = (severity_counts["high"] / total_findings) * 100
        medium_pct = (severity_counts["medium"] / total_findings) * 100
        low_pct = (severity_counts["low"] / total_findings) * 100
        info_pct = (severity_counts["info"] / total_findings) * 100
    else:
        critical_pct = high_pct = medium_pct = low_pct = info_pct = 0
    # Use ReportLab Pie chart for accurate rendering
    from reportlab.graphics.charts.piecharts import Pie
    pie = Pie()
    pie.x = 15
    pie.y = 15
    pie.width = 120
    pie.height = 120
    pie.data = [critical_pct, high_pct, medium_pct, low_pct]
    pie.labels = ['Critical', 'High', 'Medium', 'Low']
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = _safe_hex('#7C3AED')
    pie.slices[1].fillColor = _safe_hex('#8B5CF6')
    pie.slices[2].fillColor = _safe_hex('#A78BFA')
    pie.slices[3].fillColor = _safe_hex('#C4B5FD')
    pie_drawing.add(pie)
    
    # Add title
    pie_title = String(1.5*inch, 1.8*inch, "Risk Levels")
    pie_title.fontSize = 14
    pie_title.fontName = 'Helvetica-Bold'
    pie_title.fillColor = colors.white
    pie_drawing.add(pie_title)
    
    # Add legend
    legend_data = [
        ["Critical", f"{critical_pct:.1f}%"],
        ["High", f"{high_pct:.1f}%"],
        ["Medium", f"{medium_pct:.1f}%"],
        ["Low", f"{low_pct:.1f}%"]
    ]
    
    legend_table = Table(legend_data, colWidths=[1*inch, 0.7*inch])
    legend_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    
    pie_drawing.add(legend_table)
    
    story.append(pie_drawing)
    
    # 5. SEVERITY COUNTS AND OVERALL SEVERITY
    severity_data = [
        ["High:", str(severity_counts["high"])],
        ["Medium:", str(severity_counts["medium"])],
        ["Low:", str(severity_counts["low"])],
        ["Information:", str(severity_counts["info"])],
        ["", ""],
        ["Overall Severity:", f"{overall_severity:.0f}%"]
    ]
    
    severity_table = Table(severity_data, colWidths=[1.6*inch, 1.1*inch])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -2), _safe_hex('#0B1F3A')),
        ('BACKGROUND', (1, 0), (1, -2), _safe_hex('#1E293B')),
        ('BACKGROUND', (0, -1), (1, -1), _safe_hex('#7F1D1D')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, -1), (1, -1), 18),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, _safe_hex('#334155'))
    ]))
    
    story.append(severity_table)
    story.append(Spacer(1, 20))
    
    # 6. PERFORMANCE BREAKDOWN
    # Create donut charts for performance
    performance_drawing = Drawing(4*inch, 1.5*inch)
    
    # Add performance breakdown text
    performance_text = [
        "Performance Breakdown:",
        f"Blog: {severity_counts.get('high', 0) * 15} ({severity_counts.get('high', 0)}%)",
        f"Text: {severity_counts.get('medium', 0) * 20} ({severity_counts.get('medium', 0)}%)",
        f"Picture: {severity_counts.get('low', 0) * 25} ({severity_counts.get('low', 0)}%)",
        f"Video: {severity_counts.get('info', 0) * 30} ({severity_counts.get('info', 0)}%)"
    ]
    
    for i, text in enumerate(performance_text):
        p = Paragraph(text, body_style)
        story.append(p)
        if i == 0:
            story.append(Spacer(1, 10))
    
    # 7. SCAN METADATA
    story.append(Spacer(1, 20))
    
    metadata_data = [
        ["Scan ID:", scan_id],
        ["Status:", scan_status],
        ["Start Time:", start_formatted],
        ["Total Findings:", str(total_findings)],
        ["Risk Level:", risk_level],
        ["Overall Severity:", f"{overall_severity:.1f}%"]
    ]
    
    metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), _safe_hex('#0B1F3A')),
        ('BACKGROUND', (1, 0), (1, -1), _safe_hex('#1E293B')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.white),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, _safe_hex('#334155'))
    ]))
    
    story.append(metadata_table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer


def generate_dynamic_pdf(scan_data: Dict[str, Any], target_url: str) -> io.BytesIO:
    """Generate a dynamic PDF report with scan results."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    story = []
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.darkblue
    )
    
    # Title
    story.append(Paragraph("Project Echo Security Scan Report", title_style))
    story.append(Spacer(1, 20))
    
    # Scan Information
    story.append(Paragraph("Scan Information", heading_style))
    scan_info_data = [
        ["Target URL", target_url],
        ["Scan ID", scan_data.get("id", "N/A")],
        ["Scan Type", scan_data.get("type", "N/A")],
        ["Status", scan_data.get("status", "N/A")],
        ["Start Time", scan_data.get("start_time", "N/A")],
        ["End Time", scan_data.get("end_time", "N/A")],
    ]
    
    scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
    scan_info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(scan_info_table)
    story.append(Spacer(1, 20))
    
    # Findings Summary
    findings = scan_data.get("results", [])
    if findings:
        story.append(Paragraph("Findings Summary", heading_style))
        
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "Info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary_data = [["Severity", "Count"]]
        for severity, count in severity_counts.items():
            summary_data.append([severity.title(), str(count)])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        
        for i, finding in enumerate(findings[:10], 1):  # Limit to first 10 findings
            story.append(Paragraph(f"Finding {i}: {finding.get('title', 'Untitled')}", styles['Heading3']))
            
            finding_data = [
                ["Severity", finding.get("severity", "Info")],
                ["Location", finding.get("location", "N/A")],
                ["Description", finding.get("description", "N/A")[:200] + "..." if len(finding.get("description", "")) > 200 else finding.get("description", "N/A")],
                ["CWE", finding.get("cwe", "N/A")],
                ["CVE", finding.get("cve", "N/A")],
            ]
            
            finding_table = Table(finding_data, colWidths=[1.5*inch, 4.5*inch])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(finding_table)
            story.append(Spacer(1, 12))
            
            if i < len(findings[:10]):
                story.append(PageBreak())
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer
