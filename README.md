# K8s Secret Scanner

Tiny SRE tool to audit Kubernetes clusters for security misconfigurations:

- Secrets exposed as env vars (PASSWORD, SECRET, API_KEY, TOKEN)
- Privileged containers

## Why?
During security audits, many teams leak credentials via env vars. This catches it early before production.

## Install
pip install -r requirements.txt

## Usage
python scanner.py
# or inside cluster: kubectl apply and run as Job

## Example Output
[HIGH] default/payment-processor - Env var exposes secret: DB_PASSWORD
[CRITICAL] prod/bad-pod - Running as privileged

## Roadmap
- Add JSON output
- Integrate with Kyverno policy (Project 2)
- Add check for hostPath mounts

Author: Franco - K8s Security / SRE
Related: k8s-rbac-hardening, kyverno-disallow-privileged
