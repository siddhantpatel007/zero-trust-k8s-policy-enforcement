# auditors/rbac_auditor.py
# Checks RBAC (Role-Based Access Control) configurations against the baseline.
# 
# What is RBAC?
# RBAC is how Kubernetes controls who can do what. It has:
# - Roles/ClusterRoles: Define WHAT actions are allowed (e.g., "can read pods")
# - RoleBindings/ClusterRoleBindings: Define WHO gets those permissions
#
# Zero Trust RBAC principles:
# 1. No cluster-admin for regular workloads
# 2. No wildcard (*) permissions
# 3. Don't auto-mount API tokens unless needed

import time


def audit_rbac(k8s_clients, baseline):
    """
    Runs all RBAC checks and returns a list of violations.
    
    Each violation is a dictionary with:
    - type: category of the violation
    - severity: CRITICAL, HIGH, MEDIUM, or LOW
    - resource: which K8s resource is affected
    - namespace: where it was found
    - description: human-readable explanation
    - remediation: how to fix it
    - timestamp: when it was detected
    """
    violations = []
    rbac_client = k8s_clients["rbac"]
    core_client = k8s_clients["core"]
    rbac_policy = baseline["rbac"]
    
    print("\n[RBAC AUDITOR] Starting RBAC audit...")
    
    # ── CHECK 1: Cluster-Admin Bindings ──────────────────────────
    # cluster-admin has FULL access to EVERYTHING in the cluster.
    # In Zero Trust, regular service accounts should never have this.
    
    print("  Checking ClusterRoleBindings...")
    
    try:
        # Get ALL ClusterRoleBindings in the cluster
        crbs = rbac_client.list_cluster_role_binding()
        
        for crb in crbs.items:
            role_name = crb.role_ref.name
            
            # Is this binding pointing to a prohibited role?
            if role_name in rbac_policy.get("prohibited_cluster_roles", []):
                # Check who/what is bound to this role
                if crb.subjects:
                    for subject in crb.subjects:
                        # Skip system-level bindings (K8s needs these to function)
                        if subject.namespace and subject.namespace.startswith("kube-"):
                            continue
                        
                        violations.append({
                            "type": "RBAC_CLUSTER_ADMIN",
                            "severity": "CRITICAL",
                            "resource": f"ClusterRoleBinding/{crb.metadata.name}",
                            "namespace": subject.namespace or "cluster-wide",
                            "description": (
                                f"'{subject.name}' ({subject.kind}) in namespace "
                                f"'{subject.namespace}' is bound to '{role_name}'. "
                                f"This grants full cluster access."
                            ),
                            "remediation": (
                                f"Remove ClusterRoleBinding '{crb.metadata.name}' or "
                                f"replace with a scoped Role with minimum required permissions."
                            ),
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        })
    except Exception as e:
        print(f"  [WARN] Error checking ClusterRoleBindings: {e}")
    
    # ── CHECK 2: Wildcard Permissions ────────────────────────────
    # Wildcards (*) in RBAC mean "allow everything" — too broad for Zero Trust.
    # Example of bad RBAC:
    #   rules:
    #     - apiGroups: ["*"]     ← all API groups
    #       resources: ["*"]     ← all resources
    #       verbs: ["*"]         ← all actions
    
    if rbac_policy.get("prohibited_wildcards", True):
        print("  Checking for wildcard permissions...")
        
        try:
            # Check ClusterRoles
            cluster_roles = rbac_client.list_cluster_role()
            
            for cr in cluster_roles.items:
                # Skip system roles (they start with "system:")
                if cr.metadata.name.startswith("system:"):
                    continue
                
                if cr.rules:
                    for rule in cr.rules:
                        has_wildcard = False
                        wildcard_locations = []
                        
                        # Check each field for wildcards
                        if rule.verbs and "*" in rule.verbs:
                            has_wildcard = True
                            wildcard_locations.append("verbs")
                        if rule.resources and "*" in rule.resources:
                            has_wildcard = True
                            wildcard_locations.append("resources")
                        if rule.api_groups and "*" in rule.api_groups:
                            has_wildcard = True
                            wildcard_locations.append("apiGroups")
                        
                        if has_wildcard:
                            violations.append({
                                "type": "RBAC_WILDCARD",
                                "severity": "HIGH",
                                "resource": f"ClusterRole/{cr.metadata.name}",
                                "namespace": "cluster-wide",
                                "description": (
                                    f"ClusterRole '{cr.metadata.name}' uses wildcard (*) "
                                    f"in: {', '.join(wildcard_locations)}. "
                                    f"This grants overly broad permissions."
                                ),
                                "remediation": (
                                    f"Replace wildcard permissions in '{cr.metadata.name}' "
                                    f"with specific resources and verbs needed."
                                ),
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            })
        except Exception as e:
            print(f"  [WARN] Error checking wildcard permissions: {e}")
    
    # ── CHECK 3: Service Account Token Auto-Mount ────────────────
    # By default, every pod gets a token to access the K8s API.
    # Most pods don't need this. In Zero Trust, we disable it by default.
    
    if not rbac_policy.get("allow_automount_token", False):
        print("  Checking service account token auto-mounting...")
        
        try:
            # Check all namespaces (skip system namespaces)
            namespaces = core_client.list_namespace()
            skip_ns = {"kube-system", "kube-public", "kube-node-lease", "calico-system"}
            
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                if ns_name in skip_ns:
                    continue
                
                # Get all service accounts in this namespace
                service_accounts = core_client.list_namespaced_service_account(ns_name)
                
                for sa in service_accounts.items:
                    # Check if automountServiceAccountToken is True or not set
                    if sa.automount_service_account_token is not False:
                        violations.append({
                            "type": "RBAC_AUTOMOUNT_TOKEN",
                            "severity": "MEDIUM",
                            "resource": f"ServiceAccount/{sa.metadata.name}",
                            "namespace": ns_name,
                            "description": (
                                f"ServiceAccount '{sa.metadata.name}' in namespace "
                                f"'{ns_name}' has automountServiceAccountToken enabled. "
                                f"Pods using this SA will automatically get K8s API access."
                            ),
                            "remediation": (
                                f"Set automountServiceAccountToken: false on "
                                f"ServiceAccount '{sa.metadata.name}' in namespace '{ns_name}'."
                            ),
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        })
        except Exception as e:
            print(f"  [WARN] Error checking token auto-mount: {e}")
    
    print(f"  [RBAC AUDITOR] Complete. Found {len(violations)} violation(s).")
    return violations
