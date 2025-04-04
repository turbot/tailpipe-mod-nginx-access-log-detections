## Overview

Detect when error rate was increased in access logs. An unusually high error rate (HTTP 5xx status codes) often indicates serious problems with your web application, backend services, or infrastructure. This detection focuses on identifying time windows where server error rates exceed normal thresholds, which could indicate availability issues affecting user experience.

**References**:
- [SRE Book: Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
- [HTTP Status Code Registry (IANA)](https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml)
- [Nginx Error Handling](https://www.nginx.com/blog/creating-nginx-rewrite-rules/) 