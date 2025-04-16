## Overview

Detect UNION-based SQL injection attacks that attempt to join results from another query to the original query's results. UNION-based SQL injection is a technique where attackers append an additional SELECT statement to an existing query using the UNION operator. This technique allows attackers to combine results from the original query with results from an injected query, enabling them to extract data from different database tables.

This detection identifies various patterns of UNION-based SQL injection, including regular syntax, URL-encoded variants, and obfuscation techniques designed to evade detection. Attackers often use these methods to bypass security controls while still executing malicious database queries.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)