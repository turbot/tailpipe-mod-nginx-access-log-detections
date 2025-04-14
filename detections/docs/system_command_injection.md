## Overview

Detect attempts to inject and execute system commands through web requests in Nginx access logs. This detection identifies attempts to execute arbitrary system commands by exploiting vulnerabilities in web applications.

The detection focuses on identifying system command injection patterns, including command separators, system functions, and other techniques used to execute arbitrary commands on the server through Nginx web server requests.

**References**:
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) 