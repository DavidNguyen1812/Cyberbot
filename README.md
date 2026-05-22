# Cyberbot Overview

---

A Python-based security scanner designed for continuous, automated threat monitoring across Discord servers — detecting malicious file attachments and URLs in real time.
-	**Multi-Engine Threat Detection** Heuristic and signature-based scanning powered by the VirusTotal REST API, aggregating results across dozens of antivirus engines to maximize detection coverage and minimize false negatives.

- **Automated Binary Reverse Engineering** Static disassembly and decompilation of executable attachments via headless Ghidra integration, enabling deep inspection of suspicious binaries without manual analyst intervention.

- **AI-Assisted Static Code Analysis** Dual-model static analysis pipeline leveraging OpenAI and Google Gemini to identify obfuscated logic, malicious payloads, and code patterns indicative of exploitation attempts.

- **Vulnerability Pattern Matching** Command-based source-level vulnerability scanning with Semgrep, applied against extracted scripts and code snippets to surface known CVE patterns and insecure coding practices.

- **Phishing & Credential Risk Classification** Command-based Pre-trained Encoder-Transformer model for classification of phishing content and password strength assessment, providing probabilistic threat scoring on suspicious messages.

- **Local Hash Signature Database** Persistent JSON-based hash signature store for instantaneous IOC (Indicator of Compromise) lookups against previously identified threats, thus, eliminating repeated scans and wasted resources.

- **Comprehensive Audit Logging** Structured, tamper-evident scan history logs capturing file metadata, threat verdicts, timestamps, and analyst notes — supporting incident response workflows and forensic traceability.

- **Recursive Archive and Disk Image Unpacking** with Protection Against Decompression Bombs and Path Traversal Exploits.

# Repo Structure

---

```
├── CycberbotGhidraProject                        # Dedicated directory for Cyberbot to create temporary Ghidra Project during static disassembly and decompilation process
├── DownloadDirectory                             # Dedicated directory for Cyberbot to temporary store file for analysis
├── Files                                        
│   ├── Configurations
│   │   ├── CyberBotConfig.json                   # Cyberbot Configuration to securely store user admin account authentication and Discord server admin acess, chat channels in server that Cyberbot not authorized to monitor, and scanning functionality
│   │   └── OneTimeToken.json                     # Temporary stored a user requested password reset and email confirmation token
│   ├── HashedSignatures
│   │   ├── CleanSHA256Signatures.json            # Stored the SHA256 hashes of all the files and URLs already been scanned by Cyberbot as safe
│   │   └── MaliciousSHA256Signatures.json        # Stored the SHA256 hashes of all the files and URLs already been scanned by Cyberbot as malicious
│   ├── LLM Usages
│   │   ├── LLMMonthlyUsage.csv                   # Keep track of the cost of using external LLM model Gemini and OpenAi using input/output token metrics monthly 
│   │   └── LLMYearlyUsage.csv                    # Keep track of the cost of using external LLM model Gemini and OpenAi using input/output token metrics yearly
│   ├── Logs
│   │   ├── CyberBotCronTaskLog.txt               # Logging Cyberbot cron job events (e.g Updating LLM Usage chart daily, cleaning DMs with user that have admin accounts, .etc.)
│   │   ├── CyberBotDiscordCommandsLog.txt        # Logging all the events a user execute Cyberbot application commands from Discord
│   │   ├── CyberbotURLAndFileScanLog.txt         # Logging all the events Cyberbot scanning file or URL
│   │   └── OpenAIandGeminiSCATResults.txt        # Logging all SCAT results from OpenAI and Gemini
│   └── MLModels                                  # Stored all pre-trained Encoder-Transformers for phishing content detection and weak password
│       ├── CPU                                   # Models trained using a CPU                                  
│       └── MPS                                   # Models trained using Mac MPS
└── PythonScripts
    ├── GhidraDecompileScript                    
    │   └── GhidraDecompile.py                    # Instructions for Ghidrathon to disassemble a binary file
    ├── Cyberbot.py                               # Cyberbot Source Code
    ├── EncoderTransformers.py                    # The encoder-transformer architecture of the customized ML models
    └── env                                       # Change to .env, this file is where you store the important file paths and APIs to run Cyberbot
```

# Required Python Dependencies, System Binaries and API

---

| Python Dependency | Version | Source |
|---|---|---|
| discord-py | `== 2.5.2` | https://github.com/Rapptz/discord.py |
| dotenv | `== 0.9.9` | https://github.com/pedroburon/dotenv |
| filetype | `== 1.2.0` | https://github.com/h2non/filetype.py |
| openai | `== 2.26.0` | https://github.com/openai/openai-python |
| python-magic | `== 0.4.27` | http://github.com/ahupp/python-magic |
| rarfile | `== 4.2` | https://github.com/markokr/rarfile |
| aiofiles | `== 25.1.0` | https://github.com/Tinche/aiofiles |
| aiocsv | `== 1.4.0` | https://github.com/MKuranowski/aiocsv |
| numpy | `== 2.4.4` | https://numpy.org |
| pandas | `== 3.0.2` | https://pandas.pydata.org |
| matplotlib | `== 3.10.8` | https://matplotlib.org |
| fpdf | `== `1.7.2` | https://github.com/reingart/pyfpdf |
| google-genai | `== 1.66.0` | https://github.com/googleapis/python-genai |
| transformers | `== 5.7.0` | https://github.com/huggingface/transformers |
| torch | `== `2.11.0` | https://pytorch.org |
| email-validator | `== `2.3.0` | https://github.com/JoshData/python-email-validator |

| System Binary | Version | Source |
|---|---|---|
| semgrep | `>= 1.157.0` | https://semgrep.dev |
| 7z | `>= 17.05` | https://www.7-zip.org/download.html |
| unar | `>= 1.10.7` | https://www.kali.org/tools/unar/ |
| qemu-utils | `>= 10.0.2` | https://www.qemu.org/download/ |
| hdiutil (Required if the OS Cyberbot running on is MacOS) | built-in | https://ss64.com/mac/hdiutil.html |

| API Key | Source |
|---|---|
| Discord API key | https://docs.discord.com/developers/reference |
| Klipy API Key | https://klipy.com |
| Tenor API Key | https://tenor.com/gifapi/documentation |
| OpenAI API Key | https://openai.com/api/ |
| Google Gemini API Key | https://ai.google.dev/gemini-api/docs |
| Virus Total API Key | https://docs.virustotal.com/reference/overview |

# Cyberbot Discord Application Commands Reference

---

| Application Command | Purpose | Who Can Execute | Restrictions |
|---|---|---|---|
| `/create_admin_account` | Registers a new administrator account with Cyberbot, requiring a valid email address for identity verification and registration confirmation | Any server member | Each administrator account is uniquely bound to a single user and email address |
| `/confirm_admin_account` | Confirm the registration of a new administrator account with Cyberbot, requiring a valid email address and email confimration OTP code for final identity verification | Any server member | User must obtain the valid email confirmation code from invoking the /create_admin_account |
| `/remove_admin_account` | Permanently deregisters an existing administrator account from Cyberbot, requiring valid email address and password confirmation for identity verification prior to account removal | Any user with a registered administrator account | Must authenticate to confirm the deregistration process |
| `/admin_log_in` | Initiates an authenticated 1-hour administrative session, granting access to Cyberbot's server configuration and management controls | Any user with a registered administrator account | Requires administrator access privileges authorized by the server owner |
| `/admin_log_out` | Terminates the current active administrative session | Any user with a registered administrator account | The user must hold server owner-authorized administrator privileges and have an active open session |
| `/request_password_reset_token` | Requests a time-limited (3-minute) password reset token delivered to the account's registered email address | Any user with a registered administrator account | Token issuance is blocked if the account password has not satisfied the minimum password age policy of 3 hours, or if the account is currently locked |
| `/change_password` | Updates the administrator account credentials | Any user with a registered administrator account | Requires a valid password reset token for identity verification prior to any credential change |
| `/adding_admins` | Grants a server member administrative access, enabling them to view and modify Cyberbot's server configuration settings | Server Owner only | The designated server member must have an existing registered administrator account |
| `/removing_admins` | Revokes a server member's administrative access privileges | Server Owner only | The designated server member must currently hold active administrative access |
| `/viewing_cyberbot_configuration` | Retrieves and displays the current Cyberbot server configuration settings in read-only mode | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/cyberbot_config` | Modifies and applies changes to the current Cyberbot server configuration settings | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/non_monitoring_channel` | Adds or removes the current channel from Cyberbot's real-time monitoring exclusion list | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/list_supported_formats` | Retrieves and displays a comprehensive list of all file formats and content categories supported by Cyberbot's scanning and analysis engines | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/get_list_of_accessible_servers` | Retrieves and displays a complete list of servers for which the authenticated user holds active administrative access privileges | Any user with a registered administrator account | N/A |
| `/semgrep_vulnerability_scan` | Initiates a static vulnerability assessment against the target codebase using the Semgrep analysis engine to identify known security weaknesses and insecure code patterns | Any server member | N/A |
| `/phishing_email_scan` | Submits content for phishing threat classification using a pre-trained Encoder-Transformer model, providing a probabilistic threat verdict for suspicious messages and attachments | Any server member | N/A |
| `/manual_malware_scan` | Performs an on-demand malware analysis of a submitted file, inspecting for malicious attributes, suspicious indicators, and known threat signatures | Any server member | N/A |
| `/checking_file_true_format` | Determines the true file format of a submitted file by inspecting its magic bytes, identifying potential file extension spoofing or format mismatch attempts | Any server member | N/A |

# Administrator Account Documentation

---

## Overview

An administrator account is a fundamental security requirement for managing Cyberbot's server configuration settings. To register, a user must provide a valid email address and invoke the `/create_admin_account` and `/confirm_admin_account` application command.

Upon successful registration, an account record will be persisted within **CyberBotConfig.json** adhering to the following schema:

```json
{
    "User ID"                      : "<User Discord ID>",
    "User Email"                   : "<User Email Address>",
    "User Credential"              : "<SHA-512 Hash of the user password>",
    "Credential Minimum Age"       : "<Enforces the minimum password age policy>",
    "Credential Expiration Age"    : "<Enforces the maximum password age policy>",
    "Previous Credentials Used"    : ["<List of SHA-512 hashes of previously used passwords to prevent credential reuse>"],
    "Current Admin Session Period" : {"<Dictionary tracking active administrative sessions per server>"},
    "Last Time Logged In"          : "<DateTime of the most recent successful administrator authentication>",
    "Current Account Locked Out Period" : "<Remaining duration of the current account lockout, if applicable>",
    "Failed Log In Attempts"       : "<Current number of failed authentication attempts>",
    "Locked Out History"           : ["<List of DateTime entries recording each account lockout occurrence>"],
    "Total Locked Out"             : "<Cumulative count of account lockouts since creation>",
    "Total Failed Log In Attempts" : "<Cumulative count of failed authentication attempts since account creation>",
    "Accessible Servers"           : ["<List of Discord servers for which the account holds active administrative access>"],
    "Account Creation Date"        : "<DateTime of account creation>"
}
```

---

## Access Control

Possession of a registered administrator account does not implicitly grant administrative privileges within a Discord server. Access must be explicitly authorized by the server owner via the `/adding_admins` command and may be revoked at any time via the `/removing_admins` command. This design enforces a **Discretionary Access Control (DAC)** model, ensuring that access delegation remains under the authority of the server owner.

> **Note:** Server owners with a registered administrator account are automatically granted administrative access across all Discord servers they own — no additional authorization step is required.

---

## Password Policy

All administrator account passwords must conform to the following requirements:

- Minimum length of **12 characters**
- Must contain **mixed-case ASCII letters and digits**
- Must include at least one special character from the following set: `!@#$%&*_+=`
- Maximum password age of **6 months** — upon expiration, Cyberbot will dispatch an automated email reminder to the account owner prompting a credential update

Passwords are stored as **SHA-512 hashes**, salted using the user's Discord ID to ensure uniqueness and resistance against precomputed attacks.

---

## Password Reset & Update Procedure

To update account credentials, the following procedure must be followed:

1. Invoke `/request_password_reset_token` — Cyberbot will dispatch a time-limited reset token (valid for **3 minutes**) to the account's registered email address.
2. Invoke `/change_password` — provide the registered email address and the issued reset token to authenticate the credential change request.
3. Select a password update method:
   - **Custom Password** *(Recommended)* — User-defined password subject to full policy validation.
   - **Cyberbot-Generated Password** — Cyberbot generates a policy-compliant password and delivers it to the registered email address.

> Following a successful password update, a mandatory **minimum password age of 3 hours** is enforced before any subsequent credential change is permitted. This measure mitigates abuse of the password update mechanism.

### Custom Password Validation Pipeline

When a user elects to define their own password, the submitted credential undergoes the following multi-layered validation process:

| Step | Validation Check |
|------|-----------------|
| 1 | Verify the new password hash does not match the current active credential |
| 2 | Verify the new password hash has not been used in any previous credential cycle |
| 3 | Cross-reference against known data breach databases via the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3) |
| 4 | Assess password strength using two pre-trained Encoder-Transformer models trained on a [common password dataset](https://github.com/Infinitode/PWLDS) |
| 5 | Submit for final security verification via Google Gemini |

---

## Administrative Session Management

All users, including server owners, must authenticate to establish a **1-hour administrative session** before gaining read or write access to Cyberbot's configuration. Administrative sessions are **server-scoped** — a session authenticated for one Discord server does not confer access to any other server.

Upon **7 consecutive failed authentication attempts**, the account will be subjected to an automatic **3-hour lockout**, and an automated security notification will be dispatched to the account's registered email address.

---

## Server Configuration

Cyberbot maintains an independent configuration profile per Discord server in which it is deployed. Authorized administrators may interact with the server configuration via the following commands:

| Command | Access Level | Description |
|---------|-------------|-------------|
| `/viewing_cyberbot_configuration` | Read-Only | Retrieves and displays the current server configuration |
| `/cyberbot_config` | Read-Write | Modifies and applies changes to the server configuration |

### Configuration Parameters

```
Automation-Mode
    Enables or disables Cyberbot's real-time threat scanning. When enabled, any file
    attachment or URL submitted within a monitored server channel will be immediately
    subjected to analysis. When disabled, Cyberbot will suspend all automated scanning activity.

Silent-Mode
    Controls Cyberbot's verbosity during real-time scanning operations. When enabled,
    Cyberbot provides live scan progress notifications throughout the analysis process.
    When disabled, Cyberbot operates silently in the background — suppressing all output
    unless a threat is detected, at which point the malicious content is deleted and a
    descriptive remediation message is posted in the channel.

Non-Monitor-Channels
    Defines an exclusion list of server channels exempt from Cyberbot's real-time scanning,
    even when Automation-Mode is active. Channels can be added to or removed from this
    exclusion list via the /non_monitoring_channel command.
```

---

## Account Deregistration

Users may permanently deregister their administrator account by providing the registered email address and current account password for identity verification. Account deletion is subject to the same authentication lockout policy — **7 consecutive failed attempts** will result in a **3-hour account lockout** before the operation may be retried.

# Event Logging

---

## Overview

Cyberbot maintains four dedicated plain-text (`.txt`) log files, each scoped to a distinct operational domain. These logs provide a comprehensive and auditable record of all system activity, supporting incident response, forensic analysis, and operational monitoring.

---

## Log Files

### 1. `CyberBotCronTasksLog.txt`
**Purpose:** Records all events associated with Cyberbot's scheduled background tasks and automated maintenance operations.

Captured events include:

| Event | Description |
|-------|-------------|
| **One-Time Token Expiry Sweep** | Periodic inspection and invalidation of expired one-time tokens stored in `/Configurations/OneTimeToken.json` |
| **Password Expiry Enforcement** | Automated detection and flagging of administrator account passwords that have exceeded the maximum password age policy |
| **External LLM Usage Metrics Update** | Periodic recording of aggregated usage statistics for external language model API calls, including total input/output token consumption, cumulative cost, and total successful model request counts |
| **DM Chat Cleanup** | Daily purge of direct message chat history with users holding active administrator accounts |

---

### 2. `CyberBotDiscordCommandsLog.txt`
**Purpose:** Records all invocations of Cyberbot's application commands across monitored Discord servers.

Captured events include:

| Event | Description |
|-------|-------------|
| **Command Invocation** | Logs each application command call, including the invoking user, target server, command name, and execution timestamp |
| **Authentication Events** | Records administrative session initiations, terminations, and failed authentication attempts |
| **Access Control Changes** | Tracks privilege grants and revocations issued via `/adding_admins` and `/removing_admins` |
| **Configuration Changes** | Logs all modifications applied to Cyberbot's server configuration via `/cyberbot_config` |

---

### 3. `CyberbotURLAndFileScanLog.txt`
**Purpose:** Records all file attachment and URL analysis events performed by Cyberbot, encompassing both automated real-time scanning and on-demand manual scans.

Captured events include:

| Event | Description |
|-------|-------------|
| **Real-Time File Scan** | Automated analysis of file attachments detected in monitored server channels when `Automation-Mode` is active |
| **Real-Time URL Scan** | Automated analysis of URLs submitted in monitored server channels when `Automation-Mode` is active |
| **Manual File Scan** | On-demand file analysis initiated via the `/manual_malware_scan` command |
| **Threat Verdicts** | Records scan outcomes including threat classification, detection engine verdicts, file metadata, and remediation actions taken |

---

### 4. `OpenAIAndGeminiSCATResults.txt`
**Purpose:** Archives the full results of static code analysis (SCAT) performed on script file attachments by external large language model providers — Google Gemini and OpenAI GPT.

Captured events include:

| Event | Description |
|-------|-------------|
| **Static Code Analysis Report** | Complete analysis output returned by the LLM provider for each submitted script file |
| **Threat Indicators** | Identified obfuscated logic, suspicious code patterns, and potential exploitation techniques flagged during analysis |
| **Model Attribution** | Records which model (Google Gemini or OpenAI GPT) produced each analysis result, along with the associated timestamp and token usage |

---

## Log File Summary

| Log File | Scope | Primary Audience |
|----------|-------|-----------------|
| `CyberBotCronTasksLog.txt` | Scheduled tasks & background maintenance | System Administrator |
| `CyberBotDiscordCommandsLog.txt` | Application command invocations & access control | Security Auditor / Server Owner |
| `CyberbotURLAndFileScanLog.txt` | File & URL threat analysis results | Security Analyst / Incident Responder |
| `OpenAIAndGeminiSCATResults.txt` | LLM-powered static code analysis reports | Security Analyst / Malware Researcher |

---

> **Note:** All log files are append-only and retained indefinitely to ensure a complete and tamper-evident audit trail. Administrators are advised to periodically archive and back up log files to prevent data loss.








