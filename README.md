# Metasploit-Modules

# Oracle E-Business Suite CVE-2025-61882 RCE
# HTTP Request Smuggling + XSLT Injection → Remote Command Execution #

## Description

This module exploits **CVE-2025-61882**, a critical Remote Code Execution (RCE) vulnerability in **Oracle E-Business Suite (EBS)**. The flaw allows unauthenticated attackers to execute arbitrary code by leveraging a combination of HTTP request smuggling and XSLT injection.

The exploit uses Metasploit's `HttpServer` mixin to handle requests for any `.xsl` endpoint. When the target fetches the stylesheet (via XML processing in EBS), it triggers the payload.

- **CVSS Score**: 9.8 Critical
- **Affected Versions**: Oracle E-Business Suite, versions 12.2.3-12.2.14
- **Tested On**: [Fully tested on Oracle EBS 12.2.12 on Linux]

**Note**: This is a **proof-of-concept** module for educational/red teaming purposes. Use responsibly and only on authorized systems.

## Features
- Automatic payload delivery through a smuggled HTTP request
- XSLT injection allowing arbitrary command execution
- Fully interactive reverse shell support
- Compatible with Metasploit’s handler
- Customizable payloads and targets
- Built entirely using native Metasploit Ruby APIs

## Screenshots
TBD

## 🚀 Installation & Usage (Metasploit)

**1. Copy the exploit module into Metasploit’s module directory**

```
cp oracle_ebs_cve_2025_61882_rce.rb ~/.msf4/modules/exploits/multi/http/
```
**2.Start MSF**
``\msfconsole```

**3. Load the module**
```use exploit/multi/http/oracle_ebs_cve_2025_61882_rce```

**4. Configure the required parameters**
TBD

## Detection & Mitigation
- Patch Oracle EBS per [Oracle Security Alert](https://www.oracle.com/security-alerts/).
- WAF rules: Block suspicious XSL fetches.
- IDS: Monitor for `.xsl` with embedded scripts.

## References
- [Oracle Critical Patch Update](https://www.oracle.com/security-alerts/alert-cve-2025-61882.html)
- [Watchtowr blog article about the vulnerability analysis](https://labs.watchtowr.com/well-well-well-its-another-day-oracle-e-business-suite-pre-auth-rce-chain-cve-2025-61882well-well-well-its-another-day-oracle-e-business-suite-pre-auth-rce-chain-cve-2025-61882)

## Credits
- **Author**: [Mathieu Dupas](https://github.com/MatDupas)
- **Thanks**: WatchTowr for the original Python POC, Metasploit community, Rapid7 for the framework.

## License
MIT License 

**Disclaimer**: This tool is for authorized penetration testing only. The author is not responsible for misuse.
