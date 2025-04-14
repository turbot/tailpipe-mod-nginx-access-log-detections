## Overview

Detect time-based SQL injection attacks in Nginx access logs that attempt to extract information through timing delays. This detection identifies attempts to exploit SQL injection vulnerabilities by using time-delay functions to infer information about the database.

The detection focuses on identifying patterns that might cause intentional delays in database responses, including sleep functions, heavy operations, and other techniques used to perform blind SQL injection attacks through timing analysis.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 