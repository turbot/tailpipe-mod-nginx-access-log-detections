## Overview

Detect time-based SQL injection attacks that attempt to extract information by causing delays in database response times. Time-based SQL injection is a blind SQL injection technique where attackers infer information based on the time it takes for the database to respond. By injecting functions that cause the database to pause or delay execution, attackers can determine if conditions are true or false based on whether the response is delayed.

This detection identifies:
- Database-specific sleep/delay functions across multiple database platforms (SLEEP, BENCHMARK, PG_SLEEP, WAITFOR DELAY)
- Conditional time-delay patterns used to extract data bit by bit
- Various URL encoding techniques used to obfuscate time-based injection attempts
- Heavy computational functions used to cause delays when direct sleep functions are blocked

Time-based SQL injection is particularly effective against applications where other injection techniques fail, as it requires no error messages or direct output from the database query. It's a stealthy technique that can be used even when the application provides minimal feedback.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [Time-Based Blind SQL Injection Attacks](https://portswigger.net/web-security/sql-injection/blind)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)