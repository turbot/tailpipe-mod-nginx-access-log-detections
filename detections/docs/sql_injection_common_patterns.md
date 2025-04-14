# SQL Injection Common Patterns Detection

## Overview

Detect common SQL injection patterns targeting typical SQL keywords and syntax patterns in Nginx access logs. This detection identifies frequently used SQL injection techniques that might indicate an attempt to manipulate database queries, focusing on the most widespread syntax elements attackers use to compromise database security.

This detection identifies common SQL command patterns (SELECT, INSERT, DELETE, UPDATE), basic SQL injection techniques (OR 1=1), and SQL comment markers used to bypass security controls in Nginx web server logs.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)

## Detection Logic
The detection analyzes Nginx access logs for the following patterns:
- Basic SQL commands (SELECT, INSERT, DELETE, UPDATE, etc.)
- Table manipulation commands (DROP, TRUNCATE, CREATE, ALTER)
- Stored procedure execution attempts

## Examples
```
GET /search?q=SELECT * FROM users
GET /login?user=admin' OR '1'='1
GET /products?id=1; DROP TABLE users
```

## Mitigation
- Use parameterized queries or prepared statements
- Implement proper input validation
- Apply the principle of least privilege for database access
- Use web application firewalls (WAF)
- Regularly update database software and libraries 