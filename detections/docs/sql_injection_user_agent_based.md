## Overview

Detect SQL injection attacks that use the User-Agent header rather than URL parameters to bypass WAF protections or input filtering. This is an advanced evasion technique where attackers inject SQL code into the HTTP User-Agent header instead of query parameters or form fields. This method often bypasses traditional web application firewalls (WAFs) and input validation controls that focus on standard request parameters.

This detection identifies SQL injection patterns in the User-Agent header, including SQL commands (SELECT, UNION, INSERT), comment markers, logic-based patterns (OR 1=1), database-specific functions, and time-based techniques. Attackers increasingly target non-standard HTTP headers to evade security controls. Unlike parameter-based SQL injection, User-Agent-based attacks often bypass WAF rules focused on URL parameters and form fields, may not appear in web server logs that don't record full header information, and can exploit backend logging systems that directly store User-Agent values in databases.

Web applications that store User-Agent strings directly in databases without proper sanitization, log management systems that process User-Agent data through SQL queries, and analytics platforms that consume User-Agent data for statistics are particularly at risk from this attack vector.

**References**:
- [OWASP SQL Injection Prevention](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP HTTP Security Headers Guide](https://owasp.org/www-community/Security_Headers)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
- [OWASP HTTP Security Testing Guide](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) 
