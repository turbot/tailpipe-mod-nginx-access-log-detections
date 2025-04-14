## Overview

Detect attempts to inject and execute system commands through web requests in Nginx access logs. This detection identifies patterns that might indicate an attempt to execute arbitrary commands on the server by exploiting vulnerabilities in web applications.

The detection focuses on identifying common command injection patterns, including shell command separators, command execution functions, and system command patterns that might be used to compromise the server.

**References**:
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 