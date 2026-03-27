# auditors/trust_auditor.py
# Checks pod/container security configurations against the baseline.
#
# "Trust" in Zero Trust means: assume every workload is potentially
# compromised. So we lock down containers as tightly as possible:
# - No root access
# - No privileged mode
# - Resource limits enforced
# - Read-only filesystems
# - No privilege escalation

import time


def audit_trust(k8s_clients, baseline):
    """
    Inspects every pod in non-system namespaces for security violations.
    Returns a list of violations.
    """
    violations = []
    core_client = k8s_clients["core"]
    trust_policy = baseline["trust"]
    
    print("\n[TRUST AUDITOR] Starting workload trust audit...")
    
    # Get all pods across all namespaces
    all_pods = core_client.list_pod_for_all_namespaces()
    
    skip_ns = {"kube-system", "kube-public", "kube-node-lease", "calico-system",
               "calico-apiserver", "tigera-operator"}
    
    for pod in all_pods.items:
        ns_name = pod.metadata.namespace
        pod_name = pod.metadata.name
        
        if ns_name in skip_ns:
            continue
        
        print(f"  Checking pod: {ns_name}/{pod_name}")
        
        # Check each container in the pod
        containers = pod.spec.containers or []
        
        for container in containers:
            c_name = container.name
            sec_ctx = container.security_context
            resource_id = f"Pod/{pod_name}/Container/{c_name}"
            
            # ── CHECK 1: Privileged Mode ─────────────────────────
            # Privileged containers have almost full access to the host.
            # This is the most dangerous container misconfiguration.
            
            if not trust_policy.get("allow_privileged", False):
                if sec_ctx and sec_ctx.privileged:
                    violations.append({
                        "type": "TRUST_PRIVILEGED",
                        "severity": "CRITICAL",
                        "resource": resource_id,
                        "namespace": ns_name,
                        "description": (
                            f"Container '{c_name}' in pod '{pod_name}' is running "
                            f"in PRIVILEGED mode. This gives it full host access "
                            f"and breaks container isolation completely."
                        ),
                        "remediation": (
                            f"Set securityContext.privileged: false for container "
                            f"'{c_name}' in pod '{pod_name}'."
                        ),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })
            
            # ── CHECK 2: Running as Root ─────────────────────────
            # Root (UID 0) inside a container can exploit kernel
            # vulnerabilities to escape to the host system.
            
            if not trust_policy.get("allow_root", False):
                runs_as_root = False
                
                if sec_ctx and sec_ctx.run_as_user is not None:
                    if sec_ctx.run_as_user == 0:
                        runs_as_root = True
                elif not sec_ctx or sec_ctx.run_as_non_root is not True:
                    # If runAsUser isn't set and runAsNonRoot isn't True,
                    # the container MIGHT run as root (depends on image)
                    runs_as_root = True
                
                if runs_as_root:
                    violations.append({
                        "type": "TRUST_ROOT_USER",
                        "severity": "HIGH",
                        "resource": resource_id,
                        "namespace": ns_name,
                        "description": (
                            f"Container '{c_name}' in pod '{pod_name}' is running "
                            f"as root (UID 0) or may default to root. "
                            f"This increases the risk of container escape."
                        ),
                        "remediation": (
                            f"Set securityContext.runAsUser to a non-zero UID "
                            f"(e.g., 1000) and runAsNonRoot: true for container "
                            f"'{c_name}' in pod '{pod_name}'."
                        ),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })
            
            # ── CHECK 3: Resource Limits ─────────────────────────
            # Without limits, a single container can consume all CPU/memory,
            # causing denial of service for other workloads.
            
            if trust_policy.get("require_resource_limits", True):
                has_limits = (
                    container.resources and 
                    container.resources.limits and
                    container.resources.limits.get("cpu") and
                    container.resources.limits.get("memory")
                )
                
                if not has_limits:
                    violations.append({
                        "type": "TRUST_NO_RESOURCE_LIMITS",
                        "severity": "LOW",
                        "resource": resource_id,
                        "namespace": ns_name,
                        "description": (
                            f"Container '{c_name}' in pod '{pod_name}' does not "
                            f"have CPU and memory limits defined. This could lead "
                            f"to resource exhaustion (denial of service)."
                        ),
                        "remediation": (
                            f"Add resources.limits with cpu and memory values "
                            f"for container '{c_name}' in pod '{pod_name}'."
                        ),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })
            
            # ── CHECK 4: Read-Only Root Filesystem ───────────────
            # Prevents attackers from writing malicious files to the container.
            
            if trust_policy.get("require_read_only_root_fs", True):
                is_readonly = sec_ctx and sec_ctx.read_only_root_filesystem
                
                if not is_readonly:
                    violations.append({
                        "type": "TRUST_WRITABLE_FS",
                        "severity": "MEDIUM",
                        "resource": resource_id,
                        "namespace": ns_name,
                        "description": (
                            f"Container '{c_name}' in pod '{pod_name}' does not "
                            f"have a read-only root filesystem. Attackers could "
                            f"write malicious files."
                        ),
                        "remediation": (
                            f"Set securityContext.readOnlyRootFilesystem: true "
                            f"for container '{c_name}' in pod '{pod_name}'. "
                            f"Use emptyDir volumes for directories that need writes."
                        ),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })
            
            # ── CHECK 5: Privilege Escalation ────────────────────
            # Prevents a process from gaining more privileges than its parent.
            
            if not trust_policy.get("allow_privilege_escalation", False):
                allows_escalation = (
                    not sec_ctx or 
                    sec_ctx.allow_privilege_escalation is None or
                    sec_ctx.allow_privilege_escalation is True
                )
                
                if allows_escalation:
                    violations.append({
                        "type": "TRUST_PRIVILEGE_ESCALATION",
                        "severity": "MEDIUM",
                        "resource": resource_id,
                        "namespace": ns_name,
                        "description": (
                            f"Container '{c_name}' in pod '{pod_name}' allows "
                            f"privilege escalation. Processes could gain elevated "
                            f"permissions at runtime."
                        ),
                        "remediation": (
                            f"Set securityContext.allowPrivilegeEscalation: false "
                            f"for container '{c_name}' in pod '{pod_name}'."
                        ),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    })
    
    print(f"  [TRUST AUDITOR] Complete. Found {len(violations)} violation(s).")
    return violations
