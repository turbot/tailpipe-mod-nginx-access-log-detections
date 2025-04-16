## Overview

The XSS JavaScript Methods detection identifies Cross-Site Scripting (XSS) attacks that specifically target dangerous JavaScript methods and functions. This type of attack focuses on injecting code that uses powerful JavaScript methods like `eval()`, `setTimeout()`, `setInterval()`, and `Function()` constructor calls to execute arbitrary code.

This detection examines both HTTP requests and User-Agent headers for patterns indicating the use of these high-risk JavaScript methods. It focuses on identifying attempts to use methods that can execute strings as code, manipulate the DOM, access cookies, or perform other sensitive operations that could lead to security breaches.

JavaScript method-based XSS attacks are particularly dangerous because they often involve direct code execution capabilities. The `eval()` function and similar methods can execute arbitrary JavaScript passed as strings, creating a powerful vector for attackers. Similarly, timing functions like `setTimeout()` and `setInterval()` can be abused to execute code with delayed timing or repeatedly.

These attacks typically target web applications with insufficient input validation or output encoding. Attackers may attempt to inject these method calls into URL parameters, form fields, or other user-controllable inputs. By examining both request URIs and User-Agent headers, this detection can identify attackers who attempt to evade security controls by hiding their payloads in HTTP headers rather than request parameters.

This comprehensive approach helps security teams identify both reconnaissance activities and actual exploitation attempts targeting their web applications through JavaScript method-based XSS vectors.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)