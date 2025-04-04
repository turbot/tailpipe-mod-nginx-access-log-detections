## Overview

Detect when upstream server latency was increased in logs to check for potential backend service issues, network congestion, or resource constraints affecting dependent systems. In modern web architectures, many applications rely on upstream services like APIs, databases, or microservices to process requests. When these upstream services experience performance degradation, it directly impacts the overall user experience and application performance.

**References**:
- [Nginx: Upstream Module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)
- [Google SRE: Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
- [Martin Fowler: Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html) 