## Overview

Detect error-based SQL injection attacks in Nginx access logs that attempt to extract information through database error messages. This detection identifies attempts to exploit SQL injection vulnerabilities by forcing the database to generate error messages containing sensitive information.

The detection focuses on identifying patterns that might trigger database errors, including malformed SQL queries, type conversion attempts, and other techniques used to extract information through error messages in Nginx web server logs.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 