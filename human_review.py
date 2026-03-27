# human_review.py
# Manages the human review queue for HIGH and CRITICAL violations.
#
# Why human review?
# - Removing a ClusterRoleBinding might break running applications
# - Disabling privileged mode might crash containers that need it
# - These decisions need a security engineer to evaluate the impact
#
# This module:
# 1. Queues violations for review
# 2. Displays them in a clear format with remediation steps
# 3. Saves them to a JSON file for tracking

import json
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def queue_for_review(violations):
    """
    Takes HIGH and CRITICAL violations and creates a human review queue.
    Saves to a JSON file and displays in the terminal.
    """
    review_items = [v for v in violations if v["severity"] in ("HIGH", "CRITICAL")]
    
    if not review_items:
        console.print("\n[green]No violations require human review.[/green]")
        return []
    
    console.print(f"\n[bold red]═══ HUMAN REVIEW REQUIRED ═══[/bold red]")
    console.print(f"[bold]{len(review_items)} violation(s) need manual review[/bold]\n")
    
    # Display each violation in detail
    for i, v in enumerate(review_items, 1):
        sev_color = "red" if v["severity"] == "CRITICAL" else "orange3"
        
        panel_content = (
            f"[bold]Type:[/bold] {v['type']}\n"
            f"[bold]Severity:[/bold] [{sev_color}]{v['severity']}[/{sev_color}] "
            f"(Score: {v.get('score', 'N/A')})\n"
            f"[bold]Resource:[/bold] {v['resource']}\n"
            f"[bold]Namespace:[/bold] {v['namespace']}\n"
            f"[bold]Description:[/bold] {v['description']}\n"
            f"\n[bold green]Recommended Remediation:[/bold green]\n"
            f"{v['remediation']}"
        )
        
        console.print(Panel(
            panel_content,
            title=f"Review Item #{i}",
            border_style=sev_color,
        ))
    
    # Save to JSON file for tracking
    review_file = f"reports/human_review_{time.strftime('%Y%m%d_%H%M%S')}.json"
    
    review_data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_items": len(review_items),
        "critical_count": sum(1 for v in review_items if v["severity"] == "CRITICAL"),
        "high_count": sum(1 for v in review_items if v["severity"] == "HIGH"),
        "items": review_items,
    }
    
    with open(review_file, "w") as f:
        json.dump(review_data, f, indent=2)
    
    console.print(f"\n[dim]Human review queue saved to: {review_file}[/dim]")
    
    return review_items
