## Overview

Detect blind SQL injection attacks that attempt to extract information from the database using boolean conditions or time delays. Blind SQL injection occurs when an application is vulnerable to SQL injection but does not display database error messages or query results directly. Instead, attackers must infer information by observing differences in application behavior based on boolean conditions.

This detection identifies patterns commonly used in blind SQL injection, including:
- Conditional statements (AND 1=1, AND 1=2) that manipulate query logic
- String manipulation functions like SUBSTR and ASCII used to extract data character by character
- Comparison operations used to test data values
- URL-encoded variants of these techniques designed to evade detection

Blind SQL injection attacks are particularly stealthy as they don't rely on visible error messages or direct data retrieval, making them harder to detect through traditional means.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)