# Enterprise AI Security Control Plane Roadmap

This document captures the next evolution of the AI Security Monitoring Tool into an enterprise AI security and governance platform.

## Target Outcome

Create an AI security control system that can:

- route prompts and responses through a central gateway
- evaluate requests with policy and security detections before model execution
- scan responses and generated code before users receive them
- provide analyst workflows for detection, triage, and response
- map findings to OWASP LLM, OWASP Agentic, compliance frameworks, and threat intelligence

## Reference Flow

`User/App -> Connector -> AI Security Gateway -> Detection + Policy -> Allow/Redact/Warn/Block -> LLM -> Response Scanner -> User`

## Phase 1: Platform Stability

- Persistent DB and backup validation
- Versioned policy settings
- Immutable audit trail
- RBAC for admin / analyst / viewer
- Health checks and recovery procedures

## Phase 2: Gateway Control Plane

- Unified gateway request schema
- Central policy decision endpoint
- Supported provider abstraction
- Standardized enforcement actions:
  - `ALLOW`
  - `WARN`
  - `REDACT`
  - `BLOCK`
  - `ESCALATE`

## Phase 3: Enterprise Connectors

- Browser extension for ChatGPT / Gemini
- IDE extension for Cursor / Windsurf / VS Code
- SDK / middleware for internal AI apps
- Optional enterprise web proxy mode

## Phase 4: Response + Code Security

- Response leakage checks
- Generated code vulnerability scanning
- Secrets scanning
- Dependency / supply-chain risk analysis
- IaC and script safety checks

## Phase 5: AIDR

- AI Detection and Response queue
- Incident timeline and analyst triage
- Confidence + severity model
- Root cause fields:
  - who
  - what
  - why
  - how
  - remediation
  - mapped framework

## Phase 6: Governance and Compliance

- OWASP LLM Top 10
- OWASP Agentic AI risks
- MITRE ATLAS enrichment
- NIST AI RMF mapping
- ISO 42001 / SOC 2 reporting

## Recommended Near-Term Engineering Order

1. Stabilize detection and policy thresholds
2. Formalize gateway APIs for integrations
3. Add analyst action persistence to block/flag workflows
4. Strengthen posture, risk, and supply-chain modules
5. Add connector MVPs for browser and IDE workflows
6. Add response/code scanning
7. Expand compliance and executive reporting

## Immediate Deliverables Already Started

- `GET /policy/control-plane`
  - returns policy thresholds, enforcement actions, and supported sources/providers
- `POST /gateway/evaluate`
  - evaluates prompts through the detection and policy pipeline without invoking the model

These endpoints are designed to support future ChatGPT/Gemini/Cursor/Windsurf integrations while keeping the current dashboard stable.
