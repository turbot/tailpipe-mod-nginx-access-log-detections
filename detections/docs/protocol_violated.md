## Overview

Detect malformed requests and protocol violations that may indicate malicious activity. HTTP protocol violations occur when clients send requests that don't conform to standard HTTP specifications. While some violations might be caused by buggy clients or misconfigured proxies, many protocol violations are deliberate attempts to evade security controls, probe for vulnerabilities, or exploit edge cases in web server implementations.

**References**:
- [RFC 7230: HTTP/1.1 Message Syntax and Routing](https://tools.ietf.org/html/rfc7230)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
- [Nginx HTTP Core Module Configuration](https://nginx.org/en/docs/http/ngx_http_core_module.html#limit_except) 