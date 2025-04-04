## Overview

Detect when request queue size was increased in logs to check for potential capacity limitations, traffic spikes, or worker process bottlenecks affecting server responsiveness. Request queuing occurs when a web server receives more concurrent requests than it can immediately process, forcing some requests to wait in a queue until worker processes become available. Excessive queuing leads to increased latency, degraded user experience, and potential timeouts.

**References**:
- [Nginx: Worker Processes Configuration](https://nginx.org/en/docs/ngx_core_module.html#worker_processes)
- [OWASP: Denial of Service Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [FastCGI: Request Queueing](https://www.nginx.com/resources/wiki/start/topics/examples/phpfcgi/)