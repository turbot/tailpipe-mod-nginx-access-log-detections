## Overview

Detect attempts to inject and execute shell commands through web requests in Nginx access logs. This detection identifies patterns that might indicate an attempt to execute arbitrary shell commands on the server by exploiting vulnerabilities in web applications.

The detection focuses on identifying common shell command patterns, including system commands, shell interpreters, and network tools that might be used to compromise the server or exfiltrate data.

**References**:
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 