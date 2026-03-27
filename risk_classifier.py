# risk_classifier.py
# Takes violations from all auditors, assigns risk scores, and classifies them.
#
# Scoring from baseline.yaml:
#   CRITICAL = 100 points (immediate threat, needs human review)
#   HIGH     = 50  points (serious issue, needs human review)
#   MEDIUM   = 20  points (moderate concern, auto-fixable)
#   LOW      = 5   points (minor issue, auto-fixable)

from rich.console import Console
from rich.table import Table


def classify_violations(violations, baseline):
    """
    Adds a numeric risk score to each violation based on its severity.
    Returns the violations sorted by score (highest first) and total risk.
    """
    scoring = baseline["scoring"]
    
    # Add score to each violation
    for v in violations:
        v["score"] = scoring.get(v["severity"], 0)
    
    # Sort: highest risk first
    violations.sort(key=lambda x: x["score"], reverse=True)
    
    # Calculate total risk score
    total_score = sum(v["score"] for v in violations)
    
    # Count by severity
    severity_counts = {}
    for v in violations:
        sev = v["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Display results in a nice table using Rich
    console = Console()
    
    console.print(f"\n[bold]═══ RISK CLASSIFICATION RESULTS ═══[/bold]")
    console.print(f"Total violations: {len(violations)}")
    console.print(f"Total risk score: {total_score}")
    
    # Summary table
    summary_table = Table(title="Severity Summary")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    summary_table.add_column("Score Each", justify="right")
    summary_table.add_column("Subtotal", justify="right")
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        each = scoring.get(sev, 0)
        color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}.get(sev)
        summary_table.add_row(
            f"[{color}]{sev}[/{color}]",
            str(count),
            str(each),
            str(count * each),
        )
    
    console.print(summary_table)
    
    # Detailed violations table
    detail_table = Table(title="All Violations (sorted by risk)")
    detail_table.add_column("#", justify="right", width=4)
    detail_table.add_column("Severity", width=10)
    detail_table.add_column("Score", justify="right", width=6)
    detail_table.add_column("Type", width=28)
    detail_table.add_column("Namespace", width=16)
    detail_table.add_column("Resource", width=35)
    
    for i, v in enumerate(violations, 1):
        sev = v["severity"]
        color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
        detail_table.add_row(
            str(i),
            f"[{color}]{sev}[/{color}]",
            str(v["score"]),
            v["type"],
            v["namespace"],
            v["resource"][:35],
        )
    
    console.print(detail_table)
    
    return violations, total_score, severity_counts


def get_auto_fixable(violations):
    """Returns violations that can be auto-remediated (LOW and MEDIUM)."""
    return [v for v in violations if v["severity"] in ("LOW", "MEDIUM")]


def get_human_review(violations):
    """Returns violations that need human review (HIGH and CRITICAL)."""
    return [v for v in violations if v["severity"] in ("HIGH", "CRITICAL")]
