# config.py
# Loads the baseline.yaml policy file and provides it to the rest of the system.

import yaml
import sys

def load_baseline(filepath="baseline.yaml"):
    """
    Reads the baseline.yaml file and returns it as a Python dictionary.
    
    YAML files are structured text (like JSON but more readable).
    PyYAML converts them into Python dicts/lists we can work with.
    
    Example: 
      rbac:
        prohibited_wildcards: true
    
    Becomes: {"rbac": {"prohibited_wildcards": True}}
    """
    try:
        with open(filepath, "r") as f:
            baseline = yaml.safe_load(f)
        
        # Validate that required sections exist
        required_sections = ["rbac", "network", "trust", "scoring"]
        for section in required_sections:
            if section not in baseline:
                print(f"[ERROR] Missing '{section}' section in {filepath}")
                sys.exit(1)
        
        print(f"[OK] Baseline policy loaded from {filepath}")
        return baseline
    
    except FileNotFoundError:
        print(f"[ERROR] {filepath} not found. Make sure it exists in the project root.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[ERROR] Invalid YAML in {filepath}: {e}")
        sys.exit(1)


def get_k8s_client():
    """
    Creates a Kubernetes API client.
    
    This uses your kubeconfig file (~/.kube/config) which Minikube
    automatically sets up when you run 'minikube start'.
    
    Returns API clients for different K8s resource types:
    - CoreV1Api: pods, services, namespaces, service accounts
    - RbacAuthorizationV1Api: roles, rolebindings, clusterroles
    - NetworkingV1Api: network policies
    """
    from kubernetes import client, config as k8s_config
    
    try:
        # Load the kubeconfig (connection settings for your cluster)
        k8s_config.load_kube_config()
        
        return {
            "core": client.CoreV1Api(),
            "rbac": client.RbacAuthorizationV1Api(),
            "networking": client.NetworkingV1Api(),
        }
    except Exception as e:
        print(f"[ERROR] Cannot connect to Kubernetes cluster: {e}")
        print("Make sure Minikube is running: minikube status")
        sys.exit(1)
