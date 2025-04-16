## Overview

The XSS Attribute Injection detection identifies Cross-Site Scripting (XSS) attacks that exploit HTML attributes to execute malicious JavaScript. This is a sophisticated attack vector where attackers inject event handlers or other dangerous attributes into HTML elements.

This detection examines both HTTP requests and User-Agent headers for patterns indicating attribute-based XSS attempts. It focuses on identifying event handlers like `onload`, `onerror`, and `onclick`, as well as dangerous attributes such as `formaction` and custom attributes that could be used to trigger JavaScript execution.

Attribute-based XSS attacks can be particularly dangerous as they often bypass basic XSS filters that only look for script tags. By injecting event handlers into seemingly innocuous HTML elements, attackers can execute JavaScript when certain browser events are triggered. For example, injecting `onerror=alert(1)` into an image tag will execute the JavaScript when the image fails to load.

This detection looks for both common and less common event handlers, as well as attributes that can trigger script execution in modern browsers. By examining both request URIs and User-Agent headers, the detection can identify attackers who attempt to evade security controls by hiding malicious code in HTTP headers rather than request parameters. This comprehensive approach helps security teams identify potential vulnerabilities in their web applications and detect active exploitation attempts that target attribute-based XSS vectors.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)