## Overview

Detect SQL injection attacks in Nginx access logs that attempt to exploit vulnerabilities through User-Agent headers. This detection identifies attempts to inject SQL commands through manipulated User-Agent strings, which might bypass traditional input validation.

The detection focuses on identifying SQL injection patterns in User-Agent headers, including attempts to inject SQL commands, bypass authentication, or extract information through manipulated browser identification strings in Nginx web server logs.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 