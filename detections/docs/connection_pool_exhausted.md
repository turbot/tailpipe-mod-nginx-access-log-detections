## Overview

Detect when connection pool was exhausted in access logs. Web servers like Nginx maintain connection pools to efficiently handle multiple concurrent client requests. When these pools become exhausted, the server may fail to accept new connections, resulting in service unavailability, increased latency, or connection rejections that manifest as 503 Service Unavailable errors.

**References**:
- [Nginx: Connection Processing](https://nginx.org/en/docs/http/ngx_http_core_module.html#connections)
- [Nginx: Tuning for Performance](https://www.nginx.com/blog/tuning-nginx/)
- [OWASP: Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)