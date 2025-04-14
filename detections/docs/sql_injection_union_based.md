## Overview

Detect UNION-based SQL injection attacks in Nginx access logs that attempt to join results from another query to the original query's results. This detection identifies attempts to exploit SQL injection vulnerabilities by using the UNION operator to combine the results of multiple SELECT statements.

The detection focuses on identifying UNION-based SQL injection patterns, including various encoding and obfuscation techniques that might be used to bypass security controls in Nginx web server configurations.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 