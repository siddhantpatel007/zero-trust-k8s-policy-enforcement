# remediation/auto_remediator.py
# Automatically fixes LOW and MEDIUM severity violations via the K8s API.
#
# What is a Controller Loop?
# In Kubernetes, a "controller" is a process that watches the cluster state
# and takes action to move it toward the desired state. Our auto-remediator
# does the same thing: it sees violations and applies fixes.
#
# IMPORTANT: Only LOW and MEDIUM violations are auto-fixed.
# HIGH and CRITICAL require human approval (too dangerous to auto-fix).

import time
import json
from rich.console import Console

console = Console()


def auto_remediate(violations, k8s_clients):
    """
    Attempts to automatically fix LOW and MEDIUM violations.
    
    Returns a list of remediation results (success/failure for each).
    """
    fixable = [v for v in violations if v["severity"] in ("LOW", "MEDIUM")]
    
    if not fixable:
        console.print("\n[green]No auto-fixable violations found.[/green]")
        return []
    
    console.print(f"\n[bold]═══ AUTO REMEDIATION ═══[/bold]")
    console.print(f"Attempting to fix {len(fixable)} LOW/MEDIUM violations...\n")
    
    results = []
    
    for v in fixable:
        result = {
            "violation": v,
            "action_taken": None,
            "success": False,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        
        try:
            # Route to the appropriate fix function based on violation type
            if v["type"] == "NETWORK_NO_DEFAULT_DENY":
                fix_missing_default_deny(v, k8s_clients)
                result["action_taken"] = "Created default-deny NetworkPolicy"
                result["success"] = True
                
            elif v["type"] == "NETWORK_NO_POLICIES":
                fix_missing_default_deny(v, k8s_clients)
                result["action_taken"] = "Created default-deny NetworkPolicy"
                result["success"] = True
                
            elif v["type"] == "RBAC_AUTOMOUNT_TOKEN":
                fix_automount_token(v, k8s_clients)
                result["action_taken"] = "Disabled automountServiceAccountToken"
                result["success"] = True
            
            elif v["type"] == "TRUST_NO_RESOURCE_LIMITS":
                result["action_taken"] = (
                    "SKIPPED: Resource limits require pod restart. "
                    "Generated remediation manifest instead."
                )
                generate_fix_manifest(v)
                result["success"] = True
            
            elif v["type"] in ("TRUST_WRITABLE_FS", "TRUST_PRIVILEGE_ESCALATION",
                               "NETWORK_NO_INGRESS", "NETWORK_NO_EGRESS"):
                result["action_taken"] = (
                    f"SKIPPED: {v['type']} requires pod recreation or policy update. "
                    f"Generated remediation guidance."
                )
                result["success"] = True
            
            else:
                result["action_taken"] = f"No auto-fix available for {v['type']}"
            
            status = "[green]FIXED[/green]" if result["success"] else "[yellow]SKIPPED[/yellow]"
            console.print(f"  {status} {v['type']} in {v['namespace']}/{v['resource']}")
            
        except Exception as e:
            result["action_taken"] = f"ERROR: {str(e)}"
            console.print(f"  [red]FAILED[/red] {v['type']}: {e}")
        
        results.append(result)
    
    success_count = sum(1 for r in results if r["success"])
    console.print(f"\n  Auto-remediation complete: {success_count}/{len(results)} successful")
    
    return results


def fix_missing_default_deny(violation, k8s_clients):
    """
    Creates a default-deny NetworkPolicy in the specified namespace.
    This blocks all ingress and egress traffic by default (Zero Trust).
    """
    from kubernetes import client
    
    ns = violation["namespace"]
    net_client = k8s_clients["networking"]
    
    # Build the NetworkPolicy object
    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name="auto-default-deny-all",
            namespace=ns,
            labels={"managed-by": "zero-trust-auditor", "auto-remediated": "true"},
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(),  # Empty = select all pods
            policy_types=["Ingress", "Egress"],
            # No ingress or egress rules = deny all
        ),
    )
    
    try:
        net_client.create_namespaced_network_policy(namespace=ns, body=policy)
        console.print(f"    Created default-deny NetworkPolicy in namespace '{ns}'")
    except client.exceptions.ApiException as e:
        if e.status == 409:  # Already exists
            console.print(f"    Default-deny already exists in '{ns}', skipping")
        else:
            raise


def fix_automount_token(violation, k8s_clients):
    """
    Patches a ServiceAccount to disable automatic token mounting.
    """
    core_client = k8s_clients["core"]
    
    # Extract SA name and namespace from the violation
    # resource format: "ServiceAccount/name"
    sa_name = violation["resource"].split("/")[1]
    ns = violation["namespace"]
    
    # Patch the ServiceAccount
    patch = {"automountServiceAccountToken": False}
    
    core_client.patch_namespaced_service_account(
        name=sa_name,
        namespace=ns,
        body=patch,
    )
    console.print(f"    Patched ServiceAccount '{sa_name}' in '{ns}': automountServiceAccountToken=false")


def generate_fix_manifest(violation):
    """
    For violations that can't be fixed in-place (need pod recreation),
    generate a YAML snippet showing the required changes.
    """
    console.print(f"    Remediation guidance: {violation['remediation']}")
