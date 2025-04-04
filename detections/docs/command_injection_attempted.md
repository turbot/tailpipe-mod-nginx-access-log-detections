## Overview

Detect potential command injection attempts in request parameters. Command injection is a critical web security vulnerability that allows attackers to execute arbitrary operating system commands on the server hosting an application. By injecting malicious commands into web requests, attackers can compromise the entire system, access sensitive data, or pivot to other systems in the network.

**References**:
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger: OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [CWE-77: Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)
- [NIST: Security Strategies for Microservices-based Application Systems](https://csrc.nist.gov/publications/detail/sp/800-204/final) 