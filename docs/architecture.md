# AI Security Monitoring Tool - High Level Architecture

```text
                    +---------------------------+
                    |  API-based AI Providers   |
                    | OpenAI / Anthropic / etc. |
                    +------------+--------------+
                                 |
                                 | prompt/response stream
                                 v
+----------------+      +--------+---------+      +--------------------+
| React Dashboard|<---->| FastAPI Gateway  |----->| Risk Engine        |
| Alerts/Charts  | JWT  | Auth + RBAC      |      | Rules + Heuristics |
+----------------+      +--------+---------+      +---------+----------+
                                 |                          |
                                 v                          v
                        +--------+---------+       +--------+----------+
                        | PostgreSQL       |<------| Audit Hasher      |
                        | scan_logs/users  |       | immutable chain   |
                        +--------+---------+       +-------------------+
                                 |
                                 v
                     +-----------+--------------+
                     | Prometheus + Grafana     |
                     | metrics/alerts/uptime    |
                     +--------------------------+
```

Scalability:
- Stateless FastAPI instances behind load balancer
- PostgreSQL with read replicas for analytics-heavy workloads
- Async queue extension point for high-volume scanning
- Horizontal frontend/backend scaling in Kubernetes/ECS
