## Overview

Detect potential exposure of API keys or tokens in URLs. API keys, bearer tokens, and other secrets provide authentication and authorization to applications and services. When these credentials appear in URLs, they can be inadvertently exposed through browser history, server logs, referrer headers, or cached pages, creating significant security risks.

**References**:

- [OWASP: API Security Top 10 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [NIST: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [GitHub: Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning) 