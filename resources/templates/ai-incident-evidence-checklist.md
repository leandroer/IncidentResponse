# AI Incident Evidence Checklist

Record UTC timestamps, source, collector, acquisition method, correlation identifiers, retention limits, storage location, access, and SHA-256 where chain of custody requires it. Preserve raw exports; do not place secret values in this record.

## Instructions and execution

- [ ] User prompts and model responses
- [ ] System and developer instructions and versions
- [ ] Provider, model, model version, and runtime settings
- [ ] Agent configuration, orchestration graph, policies, memory, and change history
- [ ] Tool/function calls, parameters, results, approvals, denials, and retries
- [ ] Agent traces, queues, jobs, scratch state, and correlation/request IDs

## Retrieval, identity, and downstream evidence

- [ ] RAG queries, retrieved documents and versions, rankings, and source provenance
- [ ] Vector/knowledge-store changes and ingestion history
- [ ] User, agent, workload, and approver identity and authorization context
- [ ] Session, token, API-key, delegated grant, and policy-decision metadata
- [ ] Provider/API, application, data-access, network, and security telemetry
- [ ] Authoritative target-system records of reads, writes, messages, transactions, deployments, and egress

## Preservation record

| Evidence ID | Source | UTC range | Collector/method | Hash/location | Access/transfer notes |
|---|---|---|---|---|---|
| | | | | | |

## Known gaps and expiry

| Missing or ephemeral source | Expected expiry | Preservation action/owner | Scope impact |
|---|---|---|---|
| | | | |
