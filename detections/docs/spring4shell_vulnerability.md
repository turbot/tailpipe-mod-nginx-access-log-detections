## Overview

Detect when a web server received requests containing Spring4Shell exploitation patterns (CVE-2022-22965). This detection focuses on identifying attempts to exploit a critical remote code execution vulnerability in the Spring Framework, commonly known as Spring4Shell.

The Spring4Shell vulnerability affects Spring Core and allows attackers to execute arbitrary code on vulnerable systems. The vulnerability exists in the way Spring Framework handles class loading and property binding. When an attacker creates a specially crafted request to a Spring application using specific class-loading expressions, they can bypass protections and execute arbitrary code on the server.

This detection identifies multiple Spring4Shell attack patterns by scanning for malicious class-loading payloads in HTTP request URIs and User-Agent headers. These patterns include direct references to class loaders and application contexts that enable code execution, such as `class.module.classLoader.resources.context.parent.pipeline` and `springframework.context.support.FileSystemXmlApplicationContext`. The detection also accounts for URL-encoded variants of these payloads, which are common evasion techniques.

When this detection triggers, security teams should immediately verify which systems were targeted and whether they are running vulnerable versions of Spring Framework, isolate affected systems if possible, apply available patches to update Spring Framework to secure versions (Spring Framework 5.3.18+ or 5.2.20+), implement web application firewall rules to block Spring4Shell exploitation patterns, and enhance logging to identify potential compromises. This detection may occasionally trigger false positives for systems using legitimate Spring Framework functionality, particularly in development environments where debugging information might contain similar patterns.

**References**:
- [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965)
- [Spring Framework RCE - Spring4Shell Vulnerability Explained](https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/)
- [OWASP: Class Loader Manipulation](https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection)
- [MITRE ATT&CK: Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)