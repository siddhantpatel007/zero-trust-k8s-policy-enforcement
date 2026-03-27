#!/usr/bin/env python3
# main.py
# Entry point for the Zero Trust Kubernetes Policy Auditor.
# Orchestrates: Config → Audit → Classify → Remediate → Report

import os
import time
from rich.console import Console
from rich.panel import Panel

from config import load_baseline, get_k8s_client
from auditors.rbac_auditor import audit_rbac
from auditors.network_auditor import audit_network
from auditors.trust_auditor import audit_trust
from risk_classifier import classify_violations, get_auto_fixable, get_human_review
from remediation.auto_remediator import auto_remediate
from human_review import queue_for_review
from report_generator import generate_reports

console = Console()


def main():
    """Main execution flow."""
    start_time = time.time()
    
    console.print(Panel(
        "[bold cyan]Zero Trust Kubernetes Policy Auditor[/bold cyan]\n"
        "Continuous compliance monitoring & automated remediation",
        border_style="cyan",
    ))
    
    # ── Step 1: Load Configuration ───────────────────────────
    console.print("\n[bold]Step 1: Loading baseline policy...[/bold]")
    baseline = load_baseline("baseline.yaml")
    
    # ── Step 2: Connect to Kubernetes ────────────────────────
    console.print("\n[bold]Step 2: Connecting to Kubernetes cluster...[/bold]")
    k8s_clients = get_k8s_client()
    console.print("[green]Connected to cluster successfully.[/green]")
    
    # ── Step 3: Run All Auditors ─────────────────────────────
    console.print("\n[bold]Step 3: Running auditors...[/bold]")
    
    all_violations = []
    
    # Run RBAC Auditor
    rbac_violations = audit_rbac(k8s_clients, baseline)
    all_violations.extend(rbac_violations)
    
    # Run Network Auditor
    network_violations = audit_network(k8s_clients, baseline)
    all_violations.extend(network_violations)
    
    # Run Trust Auditor
    trust_violations = audit_trust(k8s_clients, baseline)
    all_violations.extend(trust_violations)
    
    # ── Step 4: Classify Risks ───────────────────────────────
    console.print("\n[bold]Step 4: Classifying violations...[/bold]")
    classified, total_score, severity_counts = classify_violations(
        all_violations, baseline
    )
    
    # ── Step 5: Auto-Remediate LOW/MEDIUM ────────────────────
    console.print("\n[bold]Step 5: Auto-remediating LOW/MEDIUM violations...[/bold]")
    remediation_results = auto_remediate(classified, k8s_clients)
    
    # ── Step 6: Queue HIGH/CRITICAL for Human Review ─────────
    console.print("\n[bold]Step 6: Processing human review queue...[/bold]")
    review_items = queue_for_review(classified)
    
    # ── Step 7: Generate Reports ─────────────────────────────
    console.print("\n[bold]Step 7: Generating reports...[/bold]")
    os.makedirs("reports", exist_ok=True)
    json_path, html_path = generate_reports(
        classified, total_score, severity_counts, remediation_results
    )
    
    # ── Summary ──────────────────────────────────────────────
    elapsed = time.time() - start_time
    
    console.print(Panel(
        f"[bold green]Audit Complete[/bold green]\n\n"
        f"Total violations found: {len(classified)}\n"
        f"Total risk score: {total_score}\n"
        f"Auto-remediated: {sum(1 for r in remediation_results if r.get('success'))}\n"
        f"Pending human review: {len(review_items)}\n"
        f"Time elapsed: {elapsed:.2f}s\n\n"
        f"Reports:\n"
        f"  JSON: {json_path}\n"
        f"  HTML: {html_path}",
        title="AUDIT SUMMARY",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
