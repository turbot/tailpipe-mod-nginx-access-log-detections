## Overview

Detect blind SQL injection attacks in Nginx access logs that attempt to extract information without visible error messages or direct output. This detection identifies attempts to exploit SQL injection vulnerabilities by inferring information through boolean conditions and other indirect methods.

The detection focuses on identifying patterns that might indicate blind SQL injection attempts, including boolean-based queries, conditional statements, and other techniques used to extract information without direct feedback in Nginx web server logs.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 