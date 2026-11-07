# Cyberbot Overview

---

A Python-based security scanner designed for continuous, automated threat monitoring across Discord servers — detecting malicious file attachments and URLs in real time.
-	**Multi-Engine Threat Detection** Heuristic and signature-based scanning powered by the VirusTotal REST API, aggregating results across dozens of antivirus engines to maximize detection coverage and minimize false negatives.

- **Automated Binary Reverse Engineering** Static disassembly and decompilation of executable attachments via headless Ghidra integration, enabling deep inspection of suspicious binaries without manual analyst intervention.

- **AI-Assisted Static Code Analysis** Dual-model static analysis pipeline leveraging OpenAI and Google Gemini to identify obfuscated logic, malicious payloads, and code patterns indicative of exploitation attempts. Partial analysis of file chunks for larger file that exceed the model context window.

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
│   │   ├── CyberBotCronTaskLog.md                # Logging Cyberbot cron job events (e.g Updating LLM Usage chart daily, cleaning DMs with user that have admin accounts, .etc.)
│   │   ├── CyberBotDiscordCommandsLog.md         # Logging all the events a user execute Cyberbot application commands from Discord
│   │   └── CyberbotURLAndFileScanLog.md          # Logging all the events Cyberbot scanning file or URL
│   └── MLModels                                  # Stored all pre-trained Encoder-Transformers for phishing content detection and weak password
│       ├── CPU                                   # Models trained using a CPU                                  
│       └── MPS                                   # Models trained using Mac MPS
└── PythonScripts
    ├── env                                       # Change to .env, this file is where you store the third-party APIs to run Cyberbot
    ├── Cyberbot.py                               # Main script to run, this script will call other modules and enable Cyberbot to function
    ├── CyberBotAdminCommandsModule.py
    ├── CyberBotAnalyticsModule.py
    ├── CyberBotArchiveDiskImageScanModule.py
    ├── CyberBotAttachmentScanModule.py
    ├── CyberBotEncoderTransformersModule.py
    ├── CyberBotEventHandlersModule.py
    ├── CyberBotFileUtilitiesModule.py
    ├── CyberBotGhidraDecompileModule.py
    ├── CyberBotGhidraIntegrationModule.py
    ├── CyberBotHashDatabaseModule.py
    ├── CyberBotLLMScanModule.py
    ├── CyberBotOtherCommandsModule.py
    ├── CyberBotRuntimeModule.py
    ├── CyberBotScanOrchestrationModule.py
    ├── CyberBotScheduledTasksModule.py
    ├── CyberBotSecurityUtilitiesModule.py
    ├── CyberBotURLPreprocessingModule.py
    ├── CyberBotURLScanModule.py   
    └── CyberBotVirusTotalModule.py
```

# Required Python Dependencies, System Binaries and API

---

| Python Dependency | Version | Source |
|---|---|---|
| discord-py | `>= 2.5.2` | https://github.com/Rapptz/discord.py |
| python-dotenv | `>= 1.2.2` | https://github.com/theskumar/python-dotenv |
| filetype | `>= 1.2.0` | https://github.com/h2non/filetype.py |
| openai | `>= 2.38.0` | https://github.com/openai/openai-python |
| python-magic | `>= 0.4.27` | http://github.com/ahupp/python-magic |
| rarfile | `>= 4.2` | https://github.com/markokr/rarfile |
| aiofiles | `>= 25.1.0` | https://github.com/Tinche/aiofiles |
| aiocsv | `>= 1.4.0` | https://github.com/MKuranowski/aiocsv |
| numpy | `>= 2.4.4` | https://numpy.org |
| pandas | `>= 3.0.2` | https://pandas.pydata.org |
| matplotlib | `>= 3.10.8` | https://matplotlib.org |
| fpdf | `>= `1.7.2` | https://github.com/reingart/pyfpdf |
| google-genai | `>= 2.7.0` | https://github.com/googleapis/python-genai |
| transformers | `>= 5.7.0` | https://github.com/huggingface/transformers |
| torch | `>= `2.11.0` | https://pytorch.org |
| email-validator | `>= `2.3.0` | https://github.com/JoshData/python-email-validator |
| bcrypt | `>= `5.0.0` | https://pypi.org/project/bcrypt/ |

| System Binary | Version | Source |
|---|---|---|
| 7zz | `>= 17.05` | https://www.7-zip.org/download.html |
| unar | `>= 1.10.7` | https://www.kali.org/tools/unar/ |
| qemu-utils | `>= 10.0.2` | https://www.qemu.org/download/ |

| API Key | Source |
|---|---|
| Discord API key | https://docs.discord.com/developers/reference |
| Klipy API Key | https://klipy.com |
| OpenAI API Key | https://openai.com/api/ |
| Google Gemini API Key | https://ai.google.dev/gemini-api/docs |
| Virus Total API Key | https://docs.virustotal.com/reference/overview |
| ScrapeOPS API Key | https://scrapeops.io |

# System Binaries Installation Guide

---

## Overview

This guide provides step-by-step installation instructions for the external system binaries required by Cyberbot's threat analysis pipeline. Ensure all binaries are correctly installed and verified before deploying Cyberbot.

---

## Table of Contents

- [Ghidra & Ghidrathon](#ghidra--ghidrathon)
  - [Linux Installation](#linux-installation)
  - [macOS Installation](#macos-installation)

---

## Ghidra & Ghidrathon

**Description:** Ghidra is an open-source reverse engineering framework developed by the National Security Agency (NSA) that enables binary disassembly and decompilation. Cyberbot leverages Ghidra in conjunction with the **Ghidrathon** Python extension to perform automated static analysis on executable file attachments, with results subsequently submitted to Google Gemini and OpenAI GPT for LLM-assisted analysis.

> **Prerequisites:**
> - Oracle Java **>= 17.0.0** is required before proceeding with the Ghidra installation.
> - Ghidrathon must be configured against the same Python interpreter and virtual environment used to run Cyberbot.

---

### Linux Installation

#### Step 1 — Install Oracle Java

**1. Download the Oracle Java JDK zip archive** for your CPU architecture from the [Oracle Java Downloads](https://www.oracle.com/java/technologies/downloads/) page.

**2. Create a dedicated JVM directory** to allow the JDK to be accessible system-wide:
```bash
sudo mkdir -p /usr/lib/jvm
```

**3. Extract the JDK archive** to the newly created directory:
```bash
sudo unzip /path/to/jdk.zip -d /usr/lib/jvm
```

**4. Configure the required environment variables** by editing the system environment file:
```bash
sudo nano /etc/environment
```
Append the following entries:
```
JAVA_HOME="/usr/lib/jvm/jdk-<version>"
PATH="$PATH:$JAVA_HOME/bin"
```

**5. Register the Java binary** with the `update-alternatives` system:
```bash
sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk-<version>/bin/java" 1
```

**6. Verify the Java installation:**
```bash
java --version
```

---

#### Step 2 — Install Ghidra

**7. Download the latest Ghidra release** zip archive from the [Ghidra Releases](https://github.com/NationalSecurityAgency/ghidra/releases) page.

**8. Extract the archive** to the `/Applications` directory (create it if it does not exist):
```bash
unzip /path/to/ghidra.zip -d /Applications
```

**9. Build the native components** required for full decompilation capabilities.

> **Note:** The Linux distribution of Ghidra does not ship with pre-built native binaries. The `buildNatives` Gradle task must be executed manually to unlock complete decompilation functionality.

```bash
cd /Applications/ghidra_x.x.x_PUBLIC/support/gradle/
./gradlew buildNatives
```

**10. Verify the Ghidra installation** by launching the Ghidra GUI:
```bash
/Applications/ghidra_x.x.x_PUBLIC/ghidraRun
```

---

#### Step 3 — Install Ghidrathon

**11. Download the latest Ghidrathon release** zip archive from the [Ghidrathon Releases](https://github.com/mandiant/Ghidrathon/releases) page.

**12. Extract the Ghidrathon archive** to a temporary working directory:
```bash
unzip /path/to/Ghidrathon.zip -d /tmp
```

**13. Install the required Python dependencies** and configure Ghidrathon against the Cyberbot virtual environment:
```bash
pip install -r /tmp/Ghidrathon-vx.x.x/requirements.txt
python /tmp/Ghidrathon-vx.x.x/ghidrathon_configure.py /Applications/ghidra_x.x.x_PUBLIC
```

**14. Verify that the Ghidrathon configuration file** was generated with the correct Python interpreter path:
```bash
cat /Applications/ghidra_x.x.x_PUBLIC/ghidrathon.save
```

**15. Deploy the Ghidrathon extension** into the Ghidra Extensions directory:
```bash
unzip /tmp/Ghidrathon-vx.x.x/Ghidrathon-vx.x.x.zip -d /Applications/ghidra_x.x.x_PUBLIC/Ghidra/Extensions/
```

**16. Disable the PyGhidra extension** to prevent conflicts with the Ghidrathon Python 3 integration:
```bash
mv /Applications/ghidra_x.x.x_PUBLIC/Ghidra/Features/PyGhidra \
   /Applications/ghidra_x.x.x_PUBLIC/Ghidra/Features/PyGhidra_Disabled
```

---

### macOS Installation

#### Step 1 — Install Oracle Java

**1. Install Oracle Java (>= 17.0.0)** by following the official [macOS Java Installation Guide](https://www.java.com/en/download/help/mac_install.html).

---

#### Step 2 — Install Ghidra

**2. Download the latest Ghidra release** zip archive from the [Ghidra Releases](https://github.com/NationalSecurityAgency/ghidra/releases) page.

**3. Extract the archive** to the `/Applications` directory:
```bash
unzip /path/to/ghidra.zip -d /Applications
```

---

#### Step 3 — Install Ghidrathon

**4. Download the latest Ghidrathon release** zip archive from the [Ghidrathon Releases](https://github.com/mandiant/Ghidrathon/releases) page.

**5. Extract the Ghidrathon archive** to a temporary working directory:
```bash
unzip /path/to/Ghidrathon.zip -d /tmp
```

**6. Install the required Python dependencies** and configure Ghidrathon against the Cyberbot virtual environment:
```bash
pip install -r /tmp/Ghidrathon-vx.x.x/requirements.txt
python /tmp/Ghidrathon-vx.x.x/ghidrathon_configure.py /Applications/ghidra_x.x.x_PUBLIC
```

**7. Verify that the Ghidrathon configuration file** was generated with the correct Python interpreter path:
```bash
cat /Applications/ghidra_x.x.x_PUBLIC/ghidrathon.save
```

**8. Deploy the Ghidrathon extension** into the Ghidra Extensions directory:
```bash
unzip /tmp/Ghidrathon-vx.x.x/Ghidrathon-vx.x.x.zip -d /Applications/ghidra_x.x.x_PUBLIC/Ghidra/Extensions/
```

**9. Disable the PyGhidra extension** to prevent conflicts with the Ghidrathon Python 3 integration:
```bash
mv /Applications/ghidra_x.x.x_PUBLIC/Ghidra/Features/PyGhidra \
   /Applications/ghidra_x.x.x_PUBLIC/Ghidra/Features/PyGhidra_Disabled
```

---

## Installation Summary

| Binary | Linux | macOS | Purpose |
|--------|-------|-------|---------|
| **Oracle Java** | Manual JDK zip extraction | Official macOS installer | Ghidra runtime dependency |
| **Ghidra** | Manual zip extraction + `buildNatives` | Manual zip extraction | Binary disassembly & decompilation |
| **Ghidrathon** | Manual configuration via `ghidrathon_configure.py` | Manual configuration via `ghidrathon_configure.py` | Python 3 scripting bridge for Ghidra |

---

> **Important:** Replace all instances of `x.x.x` and `<version>` placeholders throughout this guide with the actual version numbers corresponding to your downloaded releases.

# Cyberbot Discord Application Commands Reference

---

| Application Command | Purpose | Who Can Execute | Restrictions |
|---|---|---|---|
| `/create_admin_account` | Registers a new administrator account with Cyberbot, requiring a valid email address for identity verification and registration confirmation | Any server member | Each administrator account is uniquely bound to a single user and email address |
| `/confirm_admin_account_creation` | Confirm the registration of a new administrator account with Cyberbot, requiring a valid email address and email confimration OTP code for final identity verification | Any server member | User must obtain the valid email confirmation code from invoking the /create_admin_account |
| `/remove_admin_account` | Requesting a confirm account deletion token sent to the email address that the account registered with, requiring user to authenticate with valid email address and password for identity verification | Any user with a registered administrator account | Must authenticate to obtain the code |
| `/confirm_delete_admin_account` | Permanently deregisters an existing administrator account from Cyberbot, requiring a valid email and confirm code to authenticate prior to account removal | Any user with a registered administrator account | Must provide a valid confirm code to confirm the deregistration process |
| `/admin_log_in` | Initiates an authenticated 1-hour administrative session, granting access to Cyberbot's server configuration and management controls | Any user with a registered administrator account | Requires administrator access privileges authorized by the server owner |
| `/admin_log_out` | Terminates the current active administrative session | Any user with a registered administrator account | The user must hold server owner-authorized administrator privileges and have an active open session |
| `/request_password_reset_token` | Requests a time-limited (3-minute) password reset token delivered to the account's registered email address | Any user with a registered administrator account | Token issuance is blocked if the account password has not satisfied the minimum password age policy of 3 hours, or if the account is currently locked |
| `/change_password` | Updates the administrator account credentials | Any user with a registered administrator account | Requires a valid password reset token for identity verification prior to any credential change |
| `/adding_admins` | Grants a server member administrative access, enabling them to view and modify Cyberbot's server configuration settings | Server Owner only | The designated server member must have an existing registered administrator account |
| `/removing_admins` | Revokes a server member's administrative access privileges | Server Owner only | The designated server member must currently hold active administrative access |
| `/viewing_cyberbot_configuration` | Retrieves and displays the current Cyberbot server configuration settings in read-only mode | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/cyberbot_config` | Modifies and applies changes to the current Cyberbot server configuration settings | Any user with a registered administrator account | Requires server owner-authorized administrator privileges and have an active open session |
| `/non_monitoring_channel` | Adds or removes the current channel from Cyberbot's real-time monitoring exclusion list | Any user with a registered administrator account | Requires server owner-authorized administrator privileges and have an active open session |
| `/list_supported_formats` | Retrieves and displays a comprehensive list of all file formats and content categories supported by Cyberbot's scanning and analysis engines | Any user with a registered administrator account | Requires server owner-authorized administrator privileges and have an active open session |
| `/get_list_of_accessible_servers` | Retrieves and displays a complete list of servers for which the authenticated user holds active administrative access privileges | Any user with a registered administrator account | N/A |
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
    "User Email"                   : "<SHA-512 Hash of Email Address>",
    "User Salt"                    : "<A unique bcrypt salt value>",
    "User Credential"              : "<Bcrypt Hash of the user password and salt value>",
    "Credential Minimum Age"       : "<Enforces the minimum password age policy>",
    "Credential Expiration Age"    : "<Enforces the maximum password age policy>",
    "Previous Credentials Used"    : ["<List of BCrypt hashes of previously used passwords to prevent credential reuse>"],
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

> **Note:** Server owners with a registered administrator account are automatically granted administrative access across all Discord servers they own — no additional authorization step is required. The server owner still have to authenticate to obtain a valid admin session to configure Cyberbot.

---

## Password Policy

All administrator account passwords must conform to the following requirements:

- Minimum length of **12 characters**
- Must contain **mixed-case ASCII letters and digits**
- Must include at least one special character from the following set: `!@#$%&*_+=`
- Maximum password age of **6 months**

Passwords are stored as **BCrypt hashes**, salted to ensure uniqueness and resistance against precomputed attacks.

Email addresses are stored **SHA-512 hashes** 

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

Upon **7 consecutive failed authentication attempts**, the account will be subjected to an automatic **3-hour lockout**, and an automated security notification will be dispatched to the account's user direct message with Cyberbot.

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

Users may permanently deregister their administrator account by providing the registered email address and current account password for identity verification with command `/remove_admin_account` to obtain a confirm code via email. Users then must provide the valid confirm code and the email address that it sent to with `/confirm_delete_admin_account`. Account deletion is subject to the same authentication lockout policy — **7 consecutive failed attempts** will result in a **3-hour account lockout** before the operation may be retried.

# Event Logging

---

## Overview

Cyberbot maintains three dedicated markdown (`.md`) log files, each scoped to a distinct operational domain. These logs provide a comprehensive and auditable record of all system activity, supporting incident response, forensic analysis, and operational monitoring.

---

## Log Files

### 1. `CyberBotCronTasksLog.md`
**Purpose:** Records all events associated with Cyberbot's scheduled background tasks and automated maintenance operations.

Captured events include:

| Event | Description |
|-------|-------------|
| **One-Time Token Expiry Sweep** | Periodic inspection and invalidation of expired one-time tokens stored in `/Configurations/OneTimeToken.json` |
| **External LLM Usage Metrics Update** | Periodic recording of aggregated usage statistics for external language model API calls, including total input/output token consumption, cumulative cost, and total successful model request counts |

---

### 2. `CyberBotDiscordCommandsLog.md`
**Purpose:** Records all invocations of Cyberbot's application commands across monitored Discord servers.

Captured events include:

| Event | Description |
|-------|-------------|
| **Command Invocation** | Logs each application command call, including the invoking user, target server, command name, and execution timestamp |
| **Authentication Events** | Records administrative session initiations, terminations, and failed authentication attempts |
| **Access Control Changes** | Tracks privilege grants and revocations issued via `/adding_admins` and `/removing_admins` |
| **Configuration Changes** | Logs all modifications applied to Cyberbot's server configuration via `/cyberbot_config` |

---

### 3. `CyberbotURLAndFileScanLog.md`
**Purpose:** Records all file attachment and URL analysis events performed by Cyberbot, encompassing both automated real-time scanning and on-demand manual scans.

Captured events include:

| Event | Description |
|-------|-------------|
| **Real-Time File Scan** | Automated analysis of file attachments detected in monitored server channels when `Automation-Mode` is active |
| **Real-Time URL Scan** | Automated analysis of URLs submitted in monitored server channels when `Automation-Mode` is active |
| **Manual File Scan** | On-demand file analysis initiated via the `/manual_malware_scan` command |
| **Threat Verdicts** | Records scan outcomes including threat classification, detection engine verdicts, file metadata, and remediation actions taken |

---

## Log File Summary

| Log File | Scope | Primary Audience |
|----------|-------|-----------------|
| `CyberBotCronTasksLog.md` | Scheduled tasks & background maintenance | System Administrator |
| `CyberBotDiscordCommandsLog.md` | Application command invocations & access control | Security Auditor / Server Owner |
| `CyberbotURLAndFileScanLog.md` | File & URL threat analysis results | Security Analyst / Incident Responder |

---

> **Note:** All log files are append-only and retained indefinitely to ensure a complete and tamper-evident audit trail. Administrators are advised to periodically archive and back up log files to prevent data loss.

# CyberBot — Real-Time Threat Analysis Pipeline

**Discord security automation · Modular Python architecture · Multi-engine file and URL analysis**

CyberBot is an event-driven Discord security bot that examines URLs and file attachments posted in monitored server channels. It combines URL redirect and SSRF inspection, SHA-256 signature history, VirusTotal, recursive archive/disk-image analysis, Ghidra decompilation, and OpenAI/Google Gemini-assisted static analysis (SCAT) to produce a scan verdict and an audit log.

> **Security boundary:** A `CLEAN` result is a conclusion from the checks that completed, **not a guarantee that a URL or file is harmless**. Unsupported formats, encrypted or inaccessible content, incomplete snapshot inspection, API failures, and inconclusive analysis should not be interpreted as safe.

---

## 1. Architecture and project structure

`Cyberbot.py` is the small entry point. Features are implemented as normal, importable Python modules. `CyberBotRuntimeModule.py` provides common configuration, API clients, locks, semaphores, and scan-result types; specialist modules import shared objects and their cross-module dependencies explicitly.

```text
└── PythonScripts/
    ├── Cyberbot.py
    ├── CyberBotRuntimeModule.py
    ├── CyberBotScanOrchestrationModule.py
    ├── CyberBotEventHandlersModule.py
    ├── CyberBotAttachmentScanModule.py
    ├── CyberBotURLScanModule.py
    ├── URLPreprocessingModule.py
    ├── CyberBotVirusTotalModule.py
    ├── CyberBotHashDatabaseModule.py
    ├── ArchiveDiskImageScanModule.py
    ├── CyberBotGhidraIntegrationModule.py
    ├── GhidraDecompile.py
    ├── CyberBotLLMScanModule.py
    ├── CyberBotFileUtilitiesModule.py
    ├── CyberBotSecurityUtilitiesModule.py
    ├── CyberBotAdminCommandsModule.py
    ├── CyberBotOtherCommandsModule.py
    ├── CyberBotScheduledTasksModule.py
    ├── CyberBotAnalyticsModule.py
    └── EncoderTransformers.py
```

*This shows the directories and paths expected by the code, not a promise that the distribution creates every configuration, log, or model file.*

### Module responsibilities

| Python file | Primary responsibility |
|---|---|
| `Cyberbot.py` | Imports the feature modules and calls `Cyberbot.run(DISCORD_BOT_TOKEN)` when executed directly. |
| `CyberBotRuntimeModule.py` | Environment checks; project paths; configuration; shared Discord bot, API/model clients, locks, semaphores, tokenizers, classifiers, and result types. |
| `CyberBotEventHandlersModule.py` | `on_ready`, `on_message`, `on_message_edit`, `on_member_remove`, and `/manual_malware_scan`. |
| `CyberBotScanOrchestrationModule.py` | `CyberBotScan()`; URL/file task coordination, message verdicts, progress, and session logging. |
| `URLPreprocessingModule.py` | Redirect-chain and SSRF inspection, GIF validation, Discord CDN URL detection; owns the shared `Cyberbot` instance and its HTTP session. |
| `CyberBotURLScanModule.py` | `scanOneURL()`; per-URL deduplication, local hash history, and VirusTotal decisions. |
| `CyberBotAttachmentScanModule.py` | `scanOneAttachment()` and `analyzeAttachmentContents()`; attachment intake, extraction, VT, Ghidra, and SCAT coordination. |
| `CyberBotFileUtilitiesModule.py` | Attachment streaming/hash helpers, per-hash lock, format checks, and Discord scan/progress messages. |
| `CyberBotVirusTotalModule.py` | VirusTotal HTTP requests, retries, URL scans, and file scans. |
| `CyberBotHashDatabaseModule.py` | Clean/malicious SHA-256 history and scan-session logs. |
| `ArchiveDiskImageScanModule.py` | Recursive archive/disk-image handling, size limits, duplicate detection, snapshot-state inspection, manifest, Markdown tree. |
| `CyberBotGhidraIntegrationModule.py` | Launches Ghidra's headless decompilation workflow. |
| `GhidraDecompile.py` | Script executed **inside Ghidra/Ghidrathon**; not a normal Python module to import from the bot. |
| `CyberBotLLMScanModule.py` | OpenAI and Gemini SCAT, retry handling, partial-file analysis. |
| `CyberBotSecurityUtilitiesModule.py` | Email, password/security utilities, application-command logging, text-to-PDF conversion. |
| `CyberBotAdminCommandsModule.py` | Administrative account, session, role, password, and server-configuration commands. |
| `CyberBotOtherCommandsModule.py` | Supported formats, accessible servers, true file format, and phishing-email commands. |
| `CyberBotScheduledTasksModule.py` | Token/credential checks, role checks, and daily usage reports. |
| `CyberBotAnalyticsModule.py` | LLM usage CSVs, costs, and charts. |
| `EncoderTransformers.py` | BERT/Longformer-based local classifier models and prediction functions. |

**Import behavior:** These are conventional Python imports, not `exec()`-loaded source fragments. All modules use the same initialized runtime objects; importing the main entry point does not itself call `Cyberbot.run()`.

---

## 2. Processing flow

```text
Discord server message / edited message / manual scan
│
├── Pre-flight checks and per-server configuration
│   ├── Ignore CyberBot's own messages and unsupported DM context
│   ├── Check excluded channel (except manual scans)
│   ├── Check automation mode enable
│   └── Identify URLs and/or attachments
│
├── URL path
│   ├── Decode/check traversal patterns
│   ├── Inspect HTTP redirect hops before following them
│   │   ├── Validate scheme, hostname, port, and DNS answers
│   │   ├── Reject SSRF destinations and unsafe redirects
│   │   └── Record redirect path and final destination
│   ├── Route Discord CDN attachments into file pipeline
│   ├── Validate supported Klipy GIF links
│   └── SHA-256 history → VirusTotal URL scan → verdict
│
└── File path
    ├── Validate attachment name and size
    ├── Stream/hash attachment; detect its actual format
    ├── Share in-progress work for identical SHA-256 content
    ├── SHA-256 history / encrypted / scope checks
    ├── VirusTotal scan of root attachment
    ├── Archive or disk image?
    │   ├── Recursively inspect eligible nested containers
    │   ├── Count bytes and duplicates; apply bomb limits
    │   ├── Examine supported QEMU disk states/snapshots
    │   ├── Build Markdown filesystem tree and JSON report
    │   └── Retain unique in-scope regular files in flat scan folder
    ├── VirusTotal scan of extracted regular files
    ├── Ghidra decompilation for supported compiled binaries
    └── OpenAI / Gemini SCAT for scripts and decompiled code
        │
        └── Final verdict → hash history (when appropriate)
                          → Discord notification → cleanup → log
```

URLs and attachments are scheduled with `asyncio.create_task()` and collected with `asyncio.as_completed()`. A malicious result can be acted on as soon as its task finishes; other already-running tasks are not automatically cancelled. Separate semaphores restrict expensive operations.

---

## 3. Trigger conditions and server configuration

Automatic processing enters through the Discord `on_message` and `on_message_edit` handlers. `/manual_malware_scan` invokes the same scanning coordinator for one uploaded attachment.

| Item | Current behavior |
|---|---|
| Bot's own messages | Ignored by the main scan coordinator. |
| Direct messages | The coordinator performs a DM-context guard; it is designed for server messages. |
| New server | Initializes entries for `Non-monitoring-Channels`, `Silent-Mode`, and `Automation-Mode`, then persists them. |
| Excluded channels | Skipped for automatic scans when channel ID appears in `Non-monitoring-Channels`. |
| Automation mode | Skipped for automatic scans when Cyberbot automation mode for the server is `DISABLED`. |
| URLs | HTTP(S) URL candidates extracted from message text; repeated strings deduplicated. |
| Attachments | Discord uploads and recognized Discord CDN attachment URLs enter the file pipeline. |
| Manual scans | `/manual_malware_scan` processes an explicitly supplied attachment and bypasses automatic channel exclusions. |
| Silent mode | Controls some ordinary progress/results messages; critical verdict and other code paths may still produce messages. |


---

## 4. URL inspection and scanning pipeline

URL processing is divided between `URLPreprocessingModule.py`, `CyberBotURLScanModule.py`, `CyberBotVirusTotalModule.py`, and `CyberBotHashDatabaseModule.py`.

### Stage 4.1 — Extract and pre-validate candidate URLs

- Find HTTP(S) URL strings in message content and remove exact duplicates.
- Reject repeated URL-decoded `../` traversal sequences.
- Validate syntax, allowed HTTP(S) schemes, and required hostnames.
- Reject embedded URL credentials, nonstandard web ports, and ambiguous hostnames.

### Stage 4.2 — Inspect every redirect hop for SSRF

The preprocessor makes HTTP requests with `allow_redirects=False` and evaluates the `Location` header one hop at a time. Every next destination is validated **before** the next request. It uses DNS lookup plus a pinned resolver for each inspected connection, reducing the risk that a separately resolved private address will be contacted during this phase.

Its checks include:

| Check | Action |
|---|---|
| Loopback, private, link-local, and other non-global IP destinations | Block and issue malicious URL inspection verdict. |
| Localhost, container/internal, and cloud metadata hostname patterns | Block. |
| Non-HTTP(S) redirect target or disallowed port | Block. |
| Embedded credentials or traversal in a redirect | Block. |
| Redirect loop, excessive redirects, failed DNS/HTTP inspection, or timeout | Stop processing as **unverified** rather than claiming a confirmed SSRF verdict. |

The current configured limits are **12 redirects** and **15 seconds total URL inspection**. The log records the URL path and the reason. For a confirmed unsafe destination, CyberBot attempts to delete the originating message and stops further scanning of that message.

Example inspection record:

```text
https://example.test/start
    -> https://example.test/next
    -> http://127.0.0.1/admin

Inspection: MALICIOUS
Reason: Non-public destination in redirect path
Action: Stop URL processing; attempt message deletion
```

*The addresses above are illustrative, not actual test results.*

### Stage 4.3 — Classify the final public destination

- `https://klipy.com/gifs/` URLs undergo the Klipy provider check before being handled as ordinary URLs.
- URLs at `cdn.discordapp.com` under `/attachments/` are routed to the **attachment** scanning path.
- Other successfully inspected HTTP(S) URLs proceed to VirusTotal.

### Stage 4.4 — Check local URL SHA-256 history

`scanOneURL()` hashes the final URL, checks the local malicious and clean signature databases, and uses a per-hash lock to avoid duplicate concurrent URL work.

| Local result | Action |
|---|---|
| Previously malicious | Return malicious verdict without repeating VirusTotal analysis. |
| Previously clean | Return clean-history verdict without repeating VirusTotal analysis. |
| Unknown | Query VirusTotal. |

### Stage 4.5 — VirusTotal URL scan

The code checks available VirusTotal URL analysis, submits unknown URLs when needed, and polls for completion. A nonzero malicious-engine count becomes a malicious verdict; a completed zero-malicious count is treated as clean by the current code. Errors, rate limits that cannot be resolved, and invalid responses become unverified.

> **SSRF limitation:** This pre-inspection protects its own redirect-inspection requests. A later downloader or another HTTP client must independently apply safe destination validation; prechecking a URL cannot guarantee that a separate later network request will use the same DNS answer or redirect path.

---

## 5. File attachment scanning pipeline

The attachment workflow lives primarily in `CyberBotAttachmentScanModule.py` and `CyberBotFileUtilitiesModule.py`.

### Stage 5.1 — Validate filename and intake size

- Reject filename patterns resembling path traversal (including `../` and absolute-path patterns).
- Retrieve attachment bytes in streamed HTTPS chunks, compute SHA-256, and enforce the **300,000,000-byte** file scan limit.
- The HTTP attachment fetch uses `allow_redirects=False`.
- The current implementation can retain eligible attachment contents in RAM for later processing; its initial hashing step does not create a duplicate disk download.

### Stage 5.2 — Identify the true file format

CyberBot examines file content/signatures with its format-detection helpers instead of trusting the declared filename extension alone. It then compares the detected type against `SUPPORTED_FILE_FORMATS`.

Encrypted or unsupported root files receive an unverified/out-of-scope result rather than an automatic clean verdict.

### Stage 5.3 — Deduplicate concurrent work and check local history

- `InFlightFileScans` lets identical SHA-256 attachments share an in-progress scan result rather than create competing full scan jobs.
- `HashScanLocks` coordinates additional per-hash work.
- A previously flagged malicious hash returns a malicious result.
- A previously clean hash returns a clean-history result.
- Unknown hashes continue to full content analysis in a private temporary workspace.

### Stage 5.4 — VirusTotal root-file analysis

The full root attachment is scanned through VirusTotal. The report includes malicious, suspicious, harmless, and undetected engine counts.

| Finding | Current handling |
|---|---|
| One or more malicious detections | Flag malicious and stop that attachment's deeper analysis. |
| Suspicious detections without malicious detections | Preserve an unverified reason while other applicable checks proceed. |
| VirusTotal API error | Preserve an unverified reason; other checks may still run. |
| No malicious detections | Continue with the content-specific pipeline. |

---

## 6. Archive and disk-image analysis

`ArchiveDiskImageScanModule.py` handles recursive extraction, cumulative accounting, duplicate detection, disk-image state inspection, and a logical filesystem manifest.

### Stage 6.1 — Supported container families

**Archives and compressed streams:** ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, TAR.LZMA, TGZ, TBZ2, TXZ, GZ, RAR, BZ2, XZ, and LZMA.

**Disk image extensions:** `.dmg`, `.iso`, `.img`, `.vhd`, `.nrg`, `.vhdx`, `.vmdk`, `.qcow`, `.qcow2`, and `.udf`.

Format recognition does **not** imply every format, filesystem, parent chain, or historical state can be exhaustively inspected.

### Stage 6.2 — Cumulative byte and archive-bomb accounting

The extraction context begins by adding the **original root archive/disk-image size on disk**, then adds the bytes read from extracted entries, including nested content. It also tracks file count, duplicate files, duplicate containers, and resource limits.

The key configured limits in the supplied version are:

| Rule | Current configured value |
|---|---:|
| Individual retained scan file (`MAX_FILE_SCAN_SIZE`) | 300,000,000 bytes |
| Cumulative extracted accounting (`UNCOMPRESSED_SIZE_LIMIT`) | 50,000,000,000 bytes |
| Nested archive size (`NESTED_ARCHIVE_SIZE_LIMIT`) | 1,000,000,000 bytes |
| Disk conversion/work storage (`MAX_DISK_IMAGE_STORAGE`) | 50,000,000,000 bytes |
| Maximum virtual disk size (`MAX_VIRTUAL_DISK_SIZE`) | 50,000,000,000 bytes |
| Maximum file entries (`MAX_FILE_COUNT`) | 100,000 |
| Maximum archive depth (`MAX_ARCHIVE_LAYER`) | 7 |
| Maximum disk snapshots (`MAX_SNAPSHOTS`) | 5 |
| Maximum extraction time (`MAX_SCAN_SECONDS`) | 300 seconds |
| Duplicate archive threshold (`DUPLICATED_ARCHIVE_LIMIT`) | 4 |

The engine also checks unsafe paths, unexpected link entries, repeated archive hashes, and excessive duplicate-file ratios. It categorizes rejected/unverifiable states in the JSON report.

### Stage 6.3 — Flat scan folder with preserved logical structure

CyberBot uses two **separate representations** of extracted content:

1. **Flat scan folder:** Filesystem directory for later VirusTotal, Ghidra, and SCAT processing. It aims to retain only unique, supported, non-container regular files at or below 300 MB.
2. **JSON scan report:** Logical directory tree containing entry names, sizes, SHA-256 hashes, scan status, skipped files, nested containers, and available snapshot views. The manifest is rendered by `uncompressedFileStructure()` using Markdown-style branches (`├──`, `└──`, `│`).

Nested archives and disk images are inspected using temporary container copies, then removed instead of being left as scan targets. `.DS_Store`, Apple `._*` files, content under `__MACOSX`, oversized entries, and unsupported entries remain **visible in the report** but are excluded from the final flat scan folder.

Illustrative manifest rendering:

```text
└── Everything.zip (Directory)
    ├── Configurations (Directory)
    │   ├── CyberBotConfig.json (500 bytes; Within Cyberbot scan scope)
    │   ├── .DS_Store (6,144 bytes; macOS metadata file - Cyberbot does not scan)
    │   └── large.bin (300,000,001 bytes; File size exceeds 300 MB - Cyberbot does not scan)
    └── nested.qcow2 (1,024,000 bytes; Nested disk image)
        ├── Active disk state (Active disk state inspected)
        │   └── application.exe (12,000 bytes; Within Cyberbot scan scope)
        └── Snapshot 1 (QCOW internal snapshot inspected)
            └── old_script.py (1,500 bytes; Within Cyberbot scan scope)
```

The scan folder itself does **not** recreate this hierarchy; the report preserves it.

### Stage 6.4 — Disk-image states and snapshots

For QEMU-recognized disk formats, the code uses `qemu-img` metadata checks and attempts to convert the active state and supported internal snapshots to temporary RAW images. It then invokes `7zz` to list/read visible filesystem members without directly mounting the untrusted image on the host.

- External backing-image dependencies are rejected as unverified when the parent cannot be independently validated.
- Snapshot inventory is recorded so a failure can leave a visible **not inspected** state.
- The visible filesystem and historical-state checks depend on actual format and tool support.
- Historical APFS/Btrfs/ZFS/NTFS filesystem snapshots and optical multisession histories are **not exhaustively enumerated** by this implementation; some disk-image paths explicitly return unverified.

**Important:** Not mounting an image directly reduces one class of exposure, but QEMU and 7-Zip still parse untrusted data. Run them with restricted privileges, network access, disk quotas, and resource isolation in a production security environment.

### Stage 6.5 — Scan extracted files

After successful extraction, CyberBot walks the flat scan folder, checks hashes against local history, and submits eligible unknown files to VirusTotal. Supported binaries and scripts can also enter the later Ghidra/SCAT stages.

Manifest notes, skipped entries, or incomplete disk-state coverage must be treated as **coverage limitations**, not proof that the skipped content is harmless. In this version the parent scan's success path primarily checks the extraction function's return value, so callers must not assume all manifest warnings automatically prevent a clean result.

---

## 7. Ghidra reverse engineering

`CyberBotGhidraIntegrationModule.py` starts Ghidra's headless analyzer for supported compiled/executable formats. The Ghidra-side script, `GhidraDecompile.py`, generates a text representation of available decompiled functions.

The attachment pipeline computes the SHA-256 hash of each decompiled result and records a `CompiledHashedMap` mapping the original compiled content hash to the decompiled output hash. This enables later SCAT detections to be associated with their source binary.

A decompilation failure contributes an **unverified reason**; it must not be interpreted as evidence that a binary is clean.

---

## 8. LLM-assisted static code analysis (SCAT)

`CyberBotLLMScanModule.py` performs OpenAI and Google Gemini analysis of supported scripts and decompiled code.

1. Collect supported script files and successful Ghidra decompilation outputs.
2. Convert manageable text/script content into a PDF using `txtToPDFConversion()`.
3. Submit it to the configured OpenAI model (`GPT_MODEL`).
4. If no malicious result stops analysis, submit it to the configured Gemini model (`GEMINI_MODEL`).
5. For oversized model input, use the module's `partialLLMSCAT()` fallback where applicable.
6. Record verdicts and propagate matching compiled/decompiled hash relationships when applicable.


Model output is a heuristic analysis signal. Errors, inconclusive responses, or unsupported input can leave the file unverified. An LLM's clean answer is not a definitive malware proof.

---

## 9. Final verdicts, notifications, and cleanup

The coordinator receives individual `URLScanResult` and `FileScanResult` objects and combines their log sections.

| Scan status | Meaning in this project | Typical action |
|---|---|---|
| `malicious` | A blocking inspection finding or malicious scan result | Attempt deletion of the original Discord message for automatic scans; report reason and record applicable malicious hashes. |
| `clean` | Completed applicable checks according to current scan logic, or previously clean hash | Record applicable clean hashes and send a result when configured. |
| `unverified` | Content or a required decision could not be conclusively inspected | Report the limitation; do not mark safe solely for being unverified. |
| `error` | An unexpected processing/API failure | Record an error result and continue other independent tasks when possible. |
| `too_large` | Attachment exceeds the file scanning threshold | Stop that attachment's scan and report it as unverified. |
| `unsupported` | Unsupported input type (where a caller uses this status) | Do not claim a full scan. |

For attachment processing, each scan owner creates an isolated working directory under `DownloadDirectory/` and removes it in a `finally` block after processing. Scan-session data is appended to the Markdown log file.

Progress messages are sent for many stages when silent mode is disabled. Long scan messages may be attached as `ScanResult.md` rather than posted as a normal Discord text message.

---

## 10. Administration, local models, and scheduled tasks

The modular build includes Discord slash commands for administrator account registration, email/token confirmation, permission management, login/logout, password reset, viewing/changing server configuration, excluded channel management, manual malware scans, file type inspection, and phishing-email analysis.

The local classification functionality uses the models in `EncoderTransformers.py` and the configured BERT/Longformer tokenizer and PyTorch checkpoint files. These classifiers are distinct from OpenAI/Gemini SCAT.

Scheduled tasks perform periodic token/credential checks, permissions-related checks, and usage reporting. The source configures loops at **1 minute**, **15 seconds**, and **daily at midnight America/New_York** respectively.

---

## 11. Setup and execution

### Prerequisites

- A supported Python environment with the libraries checked by `CyberBotRuntimeModule.py` (including `discord.py`, `aiohttp`, `aiofiles`, `openai`, `google-genai`, `python-magic`, `rarfile`, `transformers`, `torch`, `bcrypt`, and the analytics libraries).
- External utilities available on `PATH`: `7zz`, `qemu-img`, `java`, and `unar`.
- A configured Ghidra installation with the expected Ghidrathon extension.
- Configuration JSON files, hash-history files, tokenizers, and pretrained model checkpoints at the paths expected by the runtime.
- Valid credentials and access for the external APIs being used.

The runtime performs dependency and installation checks during import, and the URL preprocessing module fetches ScrapeOps browser headers during import. This means even an import-based smoke test may require external resources unless it uses the supplied mocked test harness.

### Environment variables used by the supplied code

```dotenv
DISCORD_API_KEY=your_discord_token
VT_API_KEY=your_virustotal_api_key
GHIDRA_INSTALL_DIR=/path/to/ghidra
JEPLIBPATH=/path/to/jep/library
KLIPHY_API_KEY=your_klipy_api_key
SCRAPEOPS_API_KEY=your_scrapeops_api_key
EMAIL_CRED=your_email_credential

# Set provider credentials required by your installed OpenAI and Gemini SDKs.
# Exact SDK credential mechanisms depend on your environment.
```

### Launch

Place the modular Python files together in the expected `PythonScripts/` directory so that `ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent` in the runtime resolves to the project root. Then launch using the same interpreter/virtual environment as the original bot:

```bash
cd /path/to/ProjectRoot/PythonScripts
python3 Cyberbot.py
```

`GhidraDecompile.py` is launched by the Ghidra integration; it is **not** imported into normal CPython.

---

## 12. Logs and reporting

The runtime refers to these locations under the project root:

| Output | Location |
|---|---|
| URL/file scan sessions | `Files/Logs/CyberbotURLAndFileScanLog.md` |
| Application commands | `Files/Logs/CyberBotDiscordCommandsLog.md` |
| Cron/scheduled tasks | `Files/Logs/CyberBotCronTasksLog.md` |
| LLM usage accounting | `Files/LLM Usages/` |
| Clean SHA-256 history | `Files/HashedSignatures/CleanSHA256Signatures.json` |
| Malicious SHA-256 history | `Files/HashedSignatures/MaliciousSHA256Signatures.json` |
| Temporary attachment processing | `DownloadDirectory/` |
| Temporary Ghidra projects | `CyberbotGhidraProject/` |

Archive and disk-image inspection also writes a per-scan JSON report to the path provided by the attachment scanner, and uses it to generate the Markdown filesystem visualization. The attachment pipeline removes its temporary JSON report after consuming the results.

---

## 13. Known limitations and security considerations

1. **Incomplete coverage must stay unverified:** The archive manifest can contain warnings about skipped files and historical snapshots. A successful extraction return is not equivalent to comprehensive malware inspection.
2. **Redirect pre-inspection is not a permanent network authorization:** Other HTTP requests must independently enforce SSRF restrictions; the separate attachment download path is not covered by the URL pre-inspector's pinned DNS connection.
3. **Externally executed parsers are not a sandbox:** Untrusted image conversion and extraction still require OS-level isolation, bounded storage, memory, CPU, and network restrictions.
4. **Concurrency requires service limits:** Semaphore values are configured in the runtime, but VirusTotal, model providers, the filesystem, and Ghidra have their own practical limits.
5. **Models and vendor tools are external dependencies:** Provider/model availability, credentials, GhidraThon versions, and binary compatibility need verification in the deployment environment.
6. **A non-malicious result is not a guarantee:** VirusTotal engine counts, hash history, format detection, and LLM analysis may all miss malicious behavior.
7. **Free Virus Total API:** Free Virus Total API analyses is gonna be average around **40s-80s**. The premium API would be needed, if you wish to furher extended this Discord bot into an enterprise level security tool.
8. **Pre-Trained Password Strength PyTorch Models:** The pre-trained password strenght encoder-transformer has the same based architecture as the phishing email. The dataset used to train the models can be found [here](https://github.com/Infinitode/PWLDS).
9. **Pre-Trained Phishing Email Classifier PyTorch Models:** The pre-trained phishing email encoder-transformer were one of my ML project can be found [here](https://github.com/DavidNguyen1812/PhishingEmailDetector). I am new to machine learning, and most of the model architecture was written by Claude, under careful supervision.
10. **Web Search:** Cyberbot does not have any advance web search capability, so during the URL Resolution & Accessibility Validation phrase, if the the URL response status code are in the error range 400-500, then the URL will not be scan. Usually, a malicious website should be designed with less restriction in order to attract as much victim as possible, but that just an assumption.
11. **Fileless Malware:** Cyberbot can be susceptible to fileless virus, so make sure you run Cyberobt on a dedicated device like a raspberry pi, AWS EC2 instance, with a Golden Image backup.

---

## 14. Quick reference

```text
Start CyberBot:               python3 Cyberbot.py
Main scan coordinator:        CyberBotScan()
URL safety pre-processing:    processingUrls()
Concurrent URL analysis:      scanOneURL()
Concurrent attachment scan:   scanOneAttachment()
Full attachment analysis:     analyzeAttachmentContents()
Archive / disk extraction:    ArchivesDiskImagesBombAnalysisAndExtraction()
Markdown filesystem tree:     uncompressedFileStructure(scan_report_path)
VirusTotal URL scan:          virusTotalURLScan()
VirusTotal file scan:         virusTotalFileScan()
Ghidra decompilation:         ghidraDecompile()
OpenAI static analysis:       openAISCAT()
Gemini static analysis:       GeminiSCAT()
Local hash databases:         checkingCleanData(), checkingFlaggedMaliciousData(), addingHashedData()
```
