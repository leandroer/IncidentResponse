# Ransomware Containment Decision Matrix

Incident ID: __________  Decision owner: __________  Time basis: UTC

| Decision window | Evidence / condition | Candidate action | Business dependency | Authority | Validation |
|---|---|---|---|---|---|
| 0–15 min | Active encryption or destructive execution | Isolate affected endpoints; block known malicious process/hash where reliable | Clinical, manufacturing, safety, or other critical endpoint constraints | IR lead / delegated authority | EDR isolation state; encryption stopped |
| 0–30 min | Privileged credential abuse or active remote sessions | Disable/restrict accounts, revoke sessions, rotate exposed secrets | Service accounts, break-glass access, automation | Identity owner + IR lead | Session and sign-in review |
| 15–45 min | Lateral movement over SMB/RDP/admin tooling | Segment affected network paths; restrict remote administration | Domain services and production dependencies | Network owner + incident command | Flow/EDR telemetry shows blocked movement |
| 30–60 min | Compromised management plane, backup, or hypervisor | Protect control planes; suspend risky automation; isolate admin paths | Recovery capability and platform availability | Executive incident authority | Independent admin path and clean access verified |
| Ongoing | Exfiltration or extortion indicators | Restrict egress and preserve proxy, DNS, identity, and cloud logs | Customer and partner connectivity | IR + network/cloud owner | Egress attempt and data-access review |

## Decision record

- Known blast radius:
- Systems explicitly excluded from containment and why:
- Expected operational impact:
- Rollback method:
- Decision, approver, and UTC time:
- Evidence preserved before action:
- Effectiveness check and residual risk:
