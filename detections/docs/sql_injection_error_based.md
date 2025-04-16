## Overview

Detect error-based SQL injection attacks that attempt to extract information from database error messages. Error-based SQL injection is a technique where attackers deliberately cause database errors that contain sensitive information. By manipulating SQL queries to generate specific errors, attackers can extract data from the database through the error messages themselves when those messages are displayed to users.

This detection identifies:
- Database functions commonly used in error-based techniques (CONVERT, CAST, EXTRACTVALUE)
- Database structure exposure functions (VERSION, @@version, DB_NAME)
- SQL syntax that often triggers informative errors (HAVING, GROUP BY, ORDER BY)
- Database system-specific functions used for error-based extraction

Error-based SQL injection can be particularly effective against applications that display detailed database error messages to users, as it turns error handling into an attack vector.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Error-Based SQL Injection Techniques](https://www.exploit-db.com/papers/17934)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)