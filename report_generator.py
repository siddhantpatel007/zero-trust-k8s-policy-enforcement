# report_generator.py
# Generates both JSON and HTML reports from the audit results.
#
# The JSON report is machine-readable (good for integrating with other tools).
# The HTML report is a visual dashboard for presenting to stakeholders.

import json
import time
from jinja2 import Template

def generate_reports(violations, total_score, severity_counts, remediation_results):
    """
    Creates both JSON and HTML audit reports.
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    report_data = {
        "report_metadata": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": "Zero Trust K8s Auditor",
            "version": "1.0.0",
        },
        "summary": {
            "total_violations": len(violations),
            "total_risk_score": total_score,
            "severity_breakdown": severity_counts,
            "auto_remediated": sum(
                1 for r in remediation_results if r.get("success", False)
            ),
            "pending_human_review": sum(
                1 for v in violations if v["severity"] in ("HIGH", "CRITICAL")
            ),
        },
        "violations": violations,
        "remediation_results": remediation_results,
    }
    
    # ── Save JSON Report ─────────────────────────────────────
    json_path = f"reports/audit_report_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[REPORT] JSON report saved to: {json_path}")
    
    # ── Generate HTML Dashboard ──────────────────────────────
    html_path = f"reports/dashboard_{timestamp}.html"
    html_content = generate_html_dashboard(report_data)
    with open(html_path, "w") as f:
        f.write(html_content)
    print(f"[REPORT] HTML dashboard saved to: {html_path}")
    
    return json_path, html_path


def generate_html_dashboard(report_data):
    """Generates an HTML dashboard from the report data."""
    
    template_str = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero Trust K8s Audit Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0f172a; color: #e2e8f0; padding: 2rem; }
        .header { text-align: center; margin-bottom: 2rem; }
        .header h1 { font-size: 2rem; color: #38bdf8; }
        .header p { color: #94a3b8; margin-top: 0.5rem; }
        
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 1rem; margin-bottom: 2rem; }
        .card { background: #1e293b; border-radius: 12px; padding: 1.5rem;
                border: 1px solid #334155; }
        .card .label { font-size: 0.875rem; color: #94a3b8; text-transform: uppercase; }
        .card .value { font-size: 2rem; font-weight: 700; margin-top: 0.5rem; }
        .card .value.critical { color: #ef4444; }
        .card .value.high { color: #f97316; }
        .card .value.medium { color: #eab308; }
        .card .value.low { color: #22c55e; }
        .card .value.score { color: #38bdf8; }
        
        .violations-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        .violations-table th { background: #334155; padding: 0.75rem 1rem; text-align: left;
                               font-size: 0.875rem; color: #94a3b8; }
        .violations-table td { padding: 0.75rem 1rem; border-bottom: 1px solid #1e293b; }
        .violations-table tr:hover { background: #1e293b; }
        
        .severity-badge { padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem;
                          font-weight: 600; text-transform: uppercase; }
        .severity-CRITICAL { background: #7f1d1d; color: #fca5a5; }
        .severity-HIGH { background: #7c2d12; color: #fdba74; }
        .severity-MEDIUM { background: #713f12; color: #fde047; }
        .severity-LOW { background: #14532d; color: #86efac; }
        
        .section { background: #1e293b; border-radius: 12px; padding: 1.5rem;
                   border: 1px solid #334155; margin-bottom: 2rem; }
        .section h2 { color: #38bdf8; margin-bottom: 1rem; }
        
        .remediation { background: #0f172a; padding: 1rem; border-radius: 8px;
                       margin-top: 0.5rem; font-size: 0.875rem; color: #86efac; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Zero Trust Kubernetes Audit Dashboard</h1>
        <p>Generated: {{ metadata.generated_at }}</p>
    </div>
    
    <div class="summary-grid">
        <div class="card">
            <div class="label">Total Risk Score</div>
            <div class="value score">{{ summary.total_risk_score }}</div>
        </div>
        <div class="card">
            <div class="label">Critical</div>
            <div class="value critical">{{ summary.severity_breakdown.get('CRITICAL', 0) }}</div>
        </div>
        <div class="card">
            <div class="label">High</div>
            <div class="value high">{{ summary.severity_breakdown.get('HIGH', 0) }}</div>
        </div>
        <div class="card">
            <div class="label">Medium</div>
            <div class="value medium">{{ summary.severity_breakdown.get('MEDIUM', 0) }}</div>
        </div>
        <div class="card">
            <div class="label">Low</div>
            <div class="value low">{{ summary.severity_breakdown.get('LOW', 0) }}</div>
        </div>
        <div class="card">
            <div class="label">Auto-Remediated</div>
            <div class="value" style="color: #22c55e;">{{ summary.auto_remediated }}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Violations Detail</h2>
        <table class="violations-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Type</th>
                    <th>Namespace</th>
                    <th>Resource</th>
                </tr>
            </thead>
            <tbody>
                {% for v in violations %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td><span class="severity-badge severity-{{ v.severity }}">{{ v.severity }}</span></td>
                    <td>{{ v.score }}</td>
                    <td>{{ v.type }}</td>
                    <td>{{ v.namespace }}</td>
                    <td>{{ v.resource }}</td>
                </tr>
                <tr>
                    <td colspan="6">
                        <div style="color: #94a3b8; font-size: 0.85rem;">{{ v.description }}</div>
                        <div class="remediation">Remediation: {{ v.remediation }}</div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>"""
    
    template = Template(template_str)
    return template.render(
        metadata=report_data["report_metadata"],
        summary=report_data["summary"],
        violations=report_data["violations"],
    )
