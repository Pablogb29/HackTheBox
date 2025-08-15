# Penetration Testing Workflow: Ideal Order for Solving a Machine

## 1. Passive Reconnaissance  
Before touching the target directly, gather publicly available information to build context and avoid early detection.  
- **Tools:**  
  - `whois`, `nslookup`, and `dig` for domain/IP details  
  - `TheHarvester` and `Recon-ng` for gathering emails, subdomains, and other OSINT data  
  - `Shodan` and `Censys` for scanning internet-exposed services  
  - `Maltego` for visualizing relationships and connections  

## 2. Active Scanning  
Move on to active discovery to map the network surface, such as open ports and live hosts.  
- **Tools:**  
  - `nmap`: The staple for scanning open ports, service detection, OS fingerprinting, and using NSE scripts  
  - `masscan`: For fast port scanning on larger networks or when you need a quick overview  
  - `unicornscan`: As an alternative for comprehensive and asynchronous scanning  

## 3. Service Enumeration  
Dive deeper into the discovered services to understand versions, configurations, and potential weaknesses.  
- **Tools:**  
  - **Web Services:**  
    - `nikto` for quick vulnerability checks  
    - `gobuster`, `dirbuster`, or `wfuzz` for directory and file enumeration  
    - `Burp Suite` for manual testing and further enumeration  
  - **SMB/Windows Services:**  
    - `enum4linux`, `smbclient`, or `CrackMapExec` to enumerate SMB shares and configurations  
    - `Impacket` suite of tools for interacting with Windows protocols  
  - **Other Protocols:**  
    - FTP, SSH, or SNMP specific tools (e.g., `hydra` for brute-forcing if applicable)  
    - `SearchSploit` to quickly reference known exploits against detected service versions  

## 4. Vulnerability Research and Analysis  
Analyze the enumerated data to pinpoint vulnerabilities by correlating service information with known issues.  
- **Tools:**  
  - CVE databases, `Exploit-DB`, and `SearchSploit` to cross-reference vulnerabilities  
  - Vulnerability scanners like `Nessus` or `OpenVAS` (in a controlled environment) for additional insights  
  - `Metasploit` auxiliary modules for targeted vulnerability checks  

## 5. Exploitation  
With vulnerabilities in hand, craft and execute your exploit strategy to gain an initial foothold.  
- **Tools:**  
  - `Metasploit Framework`: For leveraging existing exploits and payloads  
  - Custom scripts or manual exploitation (often using Python or Bash) when tailored attacks are needed  
  - `SQLMap` for exploiting SQL injection vulnerabilities on web services  
  - `msfvenom` for generating custom payloads as necessary  

## 6. Post-Exploitation & Privilege Escalation  
Once inside, focus on expanding your control and gathering further intelligence.  
- **Tools:**  
  - **For Linux:**  
    - `LinPEAS` or `LSE` (Linux Smart Enumeration) to discover misconfigurations or escalation paths  
    - `GTFOBins` for identifying exploitable binaries  
  - **For Windows:**  
    - `WinPEAS` or `PowerUp` to enumerate potential privilege escalation vectors  
    - `Mimikatz` for extracting credentials  
  - **Network & Lateral Movement:**  
    - `BloodHound` (with `SharpHound`) to map out Active Directory relationships  
    - `Meterpreter` sessions (via `Metasploit`) for maintaining and managing access  
    - `CrackMapExec` for post-exploitation and further network reconnaissance  

## 7. Cleanup and Reporting  
Finalize your process by removing traces (in authorized engagements) and documenting every step for clarity and reproducibility.  
- **Tools:**  
  - **Cleanup:**  
    - Manual cleanup techniques or modules such as `Timestomp` (found within `Metasploit`) to alter file timestamps  
    - Custom scripts to clear logs, when permitted  
  - **Reporting:**  
    - Documentation tools like `Dradis`, `KeepNote`, or `CherryTree` to compile your findings  
    - PenTest Report templates to structure and present your results comprehensively  

---
This structured approach ensures a systematic assessment and exploitation of a target while keeping operations organized and reproducible.
