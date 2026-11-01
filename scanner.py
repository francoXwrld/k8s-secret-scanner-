#!/usr/bin/env python3
"""
K8s Secret Scanner - SRE security audit tool
Finds secrets exposed as env vars and privileged containers
"""
from kubernetes import client, config

def scan_cluster():
    try:
        config.load_kube_config()
        print("[*] Loaded kubeconfig")
    except:
        try:
            config.load_incluster_config()
            print("[*] Loaded in-cluster config")
        except:
            print("[!] No kubeconfig found - demo mode, showing example output")
            print("[HIGH] default/payment-processor - Env var exposes secret: DB_PASSWORD")
            print("[CRITICAL] prod/bad-pod - Running as privileged")
            return

    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces(watch=False)
    
    issues = 0
    for pod in pods.items:
        ns = pod.metadata.namespace
        name = pod.metadata.name
        
        for container in pod.spec.containers:
            # Check env vars
            if container.env:
                for env in container.env:
                    keywords = ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "AWS_"]
                    if any(k in env.name.upper() for k in keywords):
                        print(f"[HIGH] {ns}/{name} - Env var exposes secret: {env.name}")
                        issues += 1
            
            # Check privileged
            if container.security_context and container.security_context.privileged:
                print(f"[CRITICAL] {ns}/{name} - Running as privileged")
                issues += 1
    
    if issues == 0:
        print("[OK] No obvious secret exposure found")
    else:
        print(f"\nFound {issues} issues - review needed!")

if __name__ == "__main__":
    scan_cluster()
