## Overview

Detect requests that attempt to access restricted application files such as configuration files, source code, database files, and temporary or backup files. Such access attempts may indicate attackers trying to extract sensitive application data or internal logic.

Attackers target restricted files that may contain sensitive information such as configuration files (`.conf`, `.config`, `.ini`), backup or temporary files (`.bak`, `.old`, `.backup`, `~` files), source code files (especially those with extensions like `.inc`), database files (`.db`, `.sqlite`, `.mdb`), application metadata (`.php~`, `.php.swp`, etc.), and framework-specific directories (`/WEB-INF/`, `/META-INF/`). Accessing these files can reveal application credentials, database connection strings, API keys and secrets, business logic vulnerabilities, and internal application structure.

When this detection triggers, security teams should verify if the access attempt was successful by checking for 200 OK responses, analyze which files were targeted and what sensitive information they may contain, remove or relocate sensitive files from the web root directory, implement proper web server configuration to block access to restricted file types, configure version control systems to exclude sensitive files from deployment, add proper file extension handling in web server configuration, and consider implementing a Web Application Firewall (WAF) with file restriction rules. Some legitimate scenarios may trigger this detection, including development environments where debugging information is accessible, administrative interfaces that legitimately access configuration files, content management systems that handle various file types, and applications that generate and serve configuration files.

**References**:
- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [Securing Application Configuration Files](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#configuration-files)
- [SANS: Securing Web Application Technologies [SWAT] Checklist](https://www.sans.org/cloud-security/securing-web-application-technologies/)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 