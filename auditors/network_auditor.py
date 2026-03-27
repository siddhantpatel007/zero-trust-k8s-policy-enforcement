# auditors/network_auditor.py
# Checks network policy configurations against the baseline.
#
# What are Network Policies?
# Network Policies are Kubernetes resources that control traffic flow:
# - Ingress: incoming traffic to a pod
# - Egress: outgoing traffic from a pod
#
# Zero Trust Network principle: DENY ALL by default, then explicitly
# allow only the connections that are necessary.

import time


def audit_network(k8s_clients, baseline):
    """
    Checks every non-system namespace for required network policies.
    Returns a list of violations.
    """
    violations = []
    core_client = k8s_clients["core"]
    net_client = k8s_clients["networking"]
    net_policy = baseline["network"]
    
    print("\n[NETWORK AUDITOR] Starting network policy audit...")
    
    # Get all namespaces, skip system ones
    namespaces = core_client.list_namespace()
    skip_ns = {"kube-system", "kube-public", "kube-node-lease", "calico-system",
               "calico-apiserver", "tigera-operator"}
    
    for ns in namespaces.items:
        ns_name = ns.metadata.name
        if ns_name in skip_ns:
            continue
        
        print(f"  Checking namespace: {ns_name}")
        
        # Get all network policies in this namespace
        try:
            net_pols = net_client.list_namespaced_network_policy(ns_name)
        except Exception as e:
            print(f"  [WARN] Error listing network policies in {ns_name}: {e}")
            continue
        
        policies = net_pols.items
        
        # ── CHECK 1: Default Deny Policy Exists ─────────────────
        # A default-deny policy has an empty podSelector {} which matches
        # ALL pods, and specifies policyTypes but no allow rules.
        
        if net_policy.get("require_default_deny", True):
            has_default_deny = False
            
            for pol in policies:
                # Check if this policy matches all pods (empty selector)
                selector = pol.spec.pod_selector
                if (selector and 
                    not selector.match_labels and 
                    not selector.match_expressions):
                    # It selects all pods — check if it's a deny policy
                    policy_types = pol.spec.policy_types or []
                    
                    has_ingress_type = "Ingress" in policy_types
                    has_egress_type = "Egress" in policy_types
                    
                    # A deny-all has the type listed but no rules
                    no_ingress_rules = not pol.spec.ingress
                    no_egress_rules = not pol.spec.egress
                    
                    if ((has_ingress_type and no_ingress_rules) or 
                        (has_egress_type and no_egress_rules)):
                        has_default_deny = True
                        break
            
            if not has_default_deny:
                violations.append({
                    "type": "NETWORK_NO_DEFAULT_DENY",
                    "severity": "HIGH",
                    "resource": f"Namespace/{ns_name}",
                    "namespace": ns_name,
                    "description": (
                        f"Namespace '{ns_name}' does not have a default-deny "
                        f"NetworkPolicy. All pod-to-pod traffic is allowed by default."
                    ),
                    "remediation": (
                        f"Create a default-deny NetworkPolicy in namespace '{ns_name}' "
                        f"with empty podSelector and both Ingress and Egress policyTypes."
                    ),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
        
        # ── CHECK 2: Zero Network Policies ──────────────────────
        # If a namespace has NO network policies at all, that's worse
        
        if len(policies) == 0:
            violations.append({
                "type": "NETWORK_NO_POLICIES",
                "severity": "HIGH",
                "resource": f"Namespace/{ns_name}",
                "namespace": ns_name,
                "description": (
                    f"Namespace '{ns_name}' has ZERO network policies. "
                    f"All traffic is completely unrestricted."
                ),
                "remediation": (
                    f"Create network policies in namespace '{ns_name}'. Start with "
                    f"a default-deny policy, then add specific allow rules."
                ),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            # Skip further checks if no policies exist
            continue
        
        # ── CHECK 3: Missing Ingress Rules ──────────────────────
        if net_policy.get("require_ingress_rules", True):
            has_ingress = any(
                pol.spec.ingress for pol in policies if pol.spec.ingress
            )
            
            if not has_ingress:
                # Only flag this if we didn't already flag "no policies"
                violations.append({
                    "type": "NETWORK_NO_INGRESS",
                    "severity": "MEDIUM",
                    "resource": f"Namespace/{ns_name}",
                    "namespace": ns_name,
                    "description": (
                        f"Namespace '{ns_name}' has no explicit ingress allow rules. "
                        f"If a default-deny exists, no incoming traffic is possible."
                    ),
                    "remediation": (
                        f"Add ingress rules to allow necessary incoming traffic "
                        f"in namespace '{ns_name}'."
                    ),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
        
        # ── CHECK 4: Missing Egress Rules ───────────────────────
        if net_policy.get("require_egress_rules", True):
            has_egress = any(
                pol.spec.egress for pol in policies if pol.spec.egress
            )
            
            if not has_egress:
                violations.append({
                    "type": "NETWORK_NO_EGRESS",
                    "severity": "MEDIUM",
                    "resource": f"Namespace/{ns_name}",
                    "namespace": ns_name,
                    "description": (
                        f"Namespace '{ns_name}' has no explicit egress allow rules. "
                        f"If a default-deny exists, no outgoing traffic is possible."
                    ),
                    "remediation": (
                        f"Add egress rules to allow necessary outgoing traffic "
                        f"(at minimum, DNS on port 53) in namespace '{ns_name}'."
                    ),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
    
    print(f"  [NETWORK AUDITOR] Complete. Found {len(violations)} violation(s).")
    return violations
