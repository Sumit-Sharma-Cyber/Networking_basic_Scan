# Nmap Scan of Metasploitable — Full Port Explanations & Deliverables

## Overview

This repository contains the results and deliverables for a basic Nmap scan performed against a Metasploitable VM at `192.168.204.130`.
You will find:

* `nmap_scan_results.txt` — the raw Nmap output (all TCP ports scanned with `-sV -p-`).
* `screenshots/` — terminal screenshots showing the commands and outputs.
* `video_link.txt` — (or add in this README) a link to a short demo video explaining how to run a basic Nmap scan.

> My Video Link:-
https://www.linkedin.com/posts/sumit-sharma-9a8833303_cybersecurity-networkscanning-nmap-activity-7397483026156421120-i-8p?utm_source=share&utm_medium=member_desktop&rcm=ACoAAE2LHNABuRS9JxPq3t17Ip9rjTclWzOPqlY
---

## Command used to produce the included output

```bash
# Full TCP scan with service/version detection (human-readable output)
sudo nmap -sV -p- 192.168.204.130 -oN nmap_scan_results.txt
```

Timestamp shown in the scan output: `2025-11-06 07:35 EST`.

---

## Files included with this deliverable

* `nmap_scan_results.txt` — exact Nmap output from the command above (included).
* `README.md` — this file (explanations + reproduction steps + recommendations).
* `screenshots/` — screenshots of the terminal during scans.
* `video_link -

---

## Port-by-port explanations (from `nmap_scan_results.txt`)

Below are the ports found open on `192.168.204.130` with concise explanations of what each service is, why it matters, and quick notes about risk/typical Metasploitable behavior.

* **21/tcp — ftp (vsftpd 2.3.4)**
  Service: File Transfer Protocol (vsftpd).
  Significance: Transfers files; credentials plain-text unless FTPS used. Metasploitable may allow anonymous access or have vulnerable configurations. Useful for uploading/downloading files during labs.

* **22/tcp — ssh (OpenSSH 4.7p1 Debian 8ubuntu1)**
  Service: Secure Shell (encrypted remote login).
  Significance: Admin access point; older versions and weak/default credentials on lab VMs allow remote shells. In real infra, restrict to trusted IPs & use keys.

* **23/tcp — telnet (Linux telnetd)**
  Service: Telnet (plaintext remote login).
  Significance: Insecure; credentials are sent unencrypted and easily intercepted. Present on Metasploitable for practice exploitation.

* **25/tcp — smtp (Postfix smtpd)**
  Service: Mail Transfer Agent.
  Significance: Accepts email. Can reveal user accounts or be misconfigured as an open relay. Useful for reconnaissance of accounts.

* **53/tcp — domain (ISC BIND 9.4.2)**
  Service: DNS server.
  Significance: Resolves hostnames. Older BIND versions may have vulnerabilities; DNS can be abused (e.g., zone transfer) to enumerate hosts if misconfigured.

* **80/tcp — http (Apache httpd 2.2.8)**
  Service: HTTP (web server).
  Significance: Primary web attack surface. Metasploitable typically hosts intentionally vulnerable web apps (DVWA, mutillidae). Inspect web pages, forms, and directories.

* **111/tcp — rpcbind (RPC #100000)**
  Service: rpcbind/portmapper.
  Significance: Maps RPC program numbers to network addresses; required for RPC services like NFS. Can reveal RPC services and expose exported file systems.

* **139/tcp — netbios-ssn (Samba smbd 3.X - 4.X)**
  Service: SMB over NetBIOS (Windows file sharing).
  Significance: File sharing and authentication; can expose shares, credentials, and historically has many exploitable vectors.

* **445/tcp — netbios-ssn (Samba smbd)**
  Service: SMB/CIFS (direct TCP).
  Significance: Same as 139 but direct. Critical in Windows networks; older Samba versions on Metasploitable are intentionally vulnerable.

* **512/tcp — exec (netkit-rsh rexecd)**
  Service: rsh/rexec/remote exec.
  Significance: Legacy remote execution services often with weak or no authentication; insecure — present on Metasploitable for practice.

* **513/tcp — login?**
  Service: rlogin/login related.
  Significance: Legacy login service; insecure and often unauthenticated in lab environments.

* **514/tcp — tcpwrapped**
  Service: port appears protected/wrapped by tcp wrappers or another protector.
  Significance: Could be rsh/shell wrapped; investigate further with targeted probes.

* **1099/tcp — java-rmi (GNU Classpath grmiregistry)**
  Service: Java RMI registry.
  Significance: RMI endpoints can be abused for remote code execution if insecure or combined with deserialization issues.

* **1524/tcp — bindshell (Metasploitable root shell)**
  Service: Known Metasploitable bind shell.
  Significance: Intentionally present backdoor; connecting to this gives shell access. High-value for practice exploitation.

* **2049/tcp — nfs (RPC #100003)**
  Service: NFS (Network File System).
  Significance: Exports may be readable/writable; accessible shares can be mounted to retrieve or inject files.

* **2121/tcp — ftp (ProFTPD 1.3.1)**
  Service: Alternate FTP daemon.
  Significance: Another FTP instance; likely misconfigured or with default credentials in a lab setup.

* **3306/tcp — mysql (MySQL 5.0.51a)**
  Service: MySQL database server.
  Significance: Databases often contain sensitive data; default or weak creds common in labs allow access.

* **3632/tcp — distccd (distccd v1)**
  Service: Distributed compilation daemon.
  Significance: Known vulnerable service (certain versions allow remote command execution). Frequent Metasploitable exercise target.

* **5432/tcp — postgresql (PostgreSQL DB 8.3.x)**
  Service: PostgreSQL database.
  Significance: As with MySQL, weak creds or default accounts can give DB access.

* **5900/tcp — vnc (VNC protocol 3.3)**
  Service: VNC remote desktop.
  Significance: May be unauthenticated or use weak passwords on labs; gives remote GUI access if misconfigured.

* **6000/tcp — X11 (access denied)**
  Service: X Window System.
  Significance: If accessible, X11 can be used to display remote GUIs or intercept input; here access is denied but presence signals X services.

* **6667/tcp & 6697/tcp — irc (UnrealIRCd)**
  Service: IRC daemon.
  Significance: Chat server; specific IRC daemons (like UnrealIRCd) have had historical RCE/backdoor vulnerabilities used in CTFs and labs.

* **8009/tcp — ajp13 (Apache JServ Protocol v1.3)**
  Service: AJP connector (Tomcat/Apache integration).
  Significance: Misconfigured AJP (or exposed to the Internet) has led to severe vulnerabilities (e.g., file disclosure / remote code in past CVEs).

* **8180/tcp — http (Apache Tomcat/Coyote JSP engine 1.1)**
  Service: Tomcat HTTP connector.
  Significance: Java webapps can have admin consoles or upload endpoints; misconfigurations allow shell upload or unauthenticated admin access.

* **8787/tcp — drb (Ruby DRb RMI)**
  Service: Ruby distributed objects (DRb).
  Significance: Exposed DRb services can be abused for remote method invocation and code execution in some setups.

* **38609/tcp — mountd (RPC #100005)**
  Service: mountd (NFS mount daemon).
  Significance: Related to NFS exports; used when mounting exported file systems.

* **50148/tcp — java-rmi (GNU Classpath grmiregistry)**
  Service: Another RMI endpoint.
  Significance: Additional Java RMI registry; targetable if deserialization/RMI vulnerabilities exist.

* **59386/tcp — status (RPC #100024)**
  Service: RPC status service.
  Significance: Part of RPC ecosystem; indicates RPC activity that can reveal subsystem details.

* **59595/tcp — nlockmgr (RPC #100021)**
  Service: NFS lock manager (nlockmgr).
  Significance: Related to file locking for NFS; presence indicates NFS features are active.

---

## What each state means (quick)

* **open** — a service is listening and responded to probes. Investigate further.
* **closed** — port reachable but no service listening.
* **filtered** — packets blocked by a firewall or dropped; Nmap cannot determine if a service exists.

---

## Suggested follow-up scans (safe on Metasploitable)

```bash
# Safe informational scripts
sudo nmap --script=default,safe 192.168.204.130 -oN outputs/nse_default_safe.txt

# Vulnerability scripts (intrusive — OK on Metasploitable)
sudo nmap --script=vuln 192.168.204.130 -oN outputs/nse_vuln.txt

# Targeted service checks (example)
sudo nmap -sV -p21,22,23,80,139,445,3306,3632,1524,5900 192.168.204.130 -oN outputs/targeted_services.txt
```

---

## Remediation notes (if this were production)

* **Remove / firewall**: disable or firewall off FTP, Telnet, rsh, distccd, legacy RPCs unless explicitly required.
* **Replace insecure services**: use SFTP/SSH rather than FTP/Telnet.
* **Segment databases**: keep MySQL/Postgres accessible only from application servers or admin networks.
* **Patch & update**: upgrade BIND, Apache, Samba, OpenSSH, Tomcat, MySQL, PostgreSQL, and other packages.
* **Strong auth**: enforce unique, complex passwords and key-based SSH auth.
* **Monitor & log**: deploy host-based intrusion detection and centralized logging.

---

## Final notes & legal reminder

* The contents of this repo and the scanning performed are for learning in an isolated lab (Metasploitable).
* Never run intrusive scans or exploitation attempts against hosts you do not own or have explicit written permission to test.


## 👨‍💻 Author
**Name:** Sumit Sharma  
**Internship Program:** Security Analyst Internship 
**Date:** November 2025  
