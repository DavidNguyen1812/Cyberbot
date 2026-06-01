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
| python-dotenv | `== 1.2.2` | https://github.com/theskumar/python-dotenv |
| filetype | `== 1.2.0` | https://github.com/h2non/filetype.py |
| openai | `== 2.38.0` | https://github.com/openai/openai-python |
| python-magic | `== 0.4.27` | http://github.com/ahupp/python-magic |
| rarfile | `== 4.2` | https://github.com/markokr/rarfile |
| aiofiles | `== 25.1.0` | https://github.com/Tinche/aiofiles |
| aiocsv | `== 1.4.0` | https://github.com/MKuranowski/aiocsv |
| numpy | `== 2.4.4` | https://numpy.org |
| pandas | `== 3.0.2` | https://pandas.pydata.org |
| matplotlib | `== 3.10.8` | https://matplotlib.org |
| fpdf | `== `1.7.2` | https://github.com/reingart/pyfpdf |
| google-genai | `== 2.7.0` | https://github.com/googleapis/python-genai |
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

# System Binaries Installation Guide

---

## Overview

This guide provides step-by-step installation instructions for the external system binaries required by Cyberbot's threat analysis pipeline. Ensure all binaries are correctly installed and verified before deploying Cyberbot.

---

## Table of Contents

- [Semgrep](#semgrep)
- [Ghidra & Ghidrathon](#ghidra--ghidrathon)
  - [Linux Installation](#linux-installation)
  - [macOS Installation](#macos-installation)

---

## Semgrep

**Description:** Semgrep is an open-source, Python-based static analysis engine used by Cyberbot to perform vulnerability scanning on file attachments submitted via the `/semgrep_vulnerability_scan` command.

---

### Linux

**1. Install Semgrep via pip:**
```bash
pip install semgrep
```

**2. Create symbolic links to expose the Semgrep binaries system-wide:**
```bash
sudo ln -s ~/.local/bin/semgrep /usr/bin/semgrep
sudo ln -s ~/.local/bin/pysemgrep /usr/bin/pysemgrep
```

**3. Verify the installation:**
```bash
semgrep --version
```

---

### macOS

**1. Install Semgrep via Homebrew:**
```bash
brew install semgrep
```

**2. Verify the installation:**
```bash
semgrep --version
```

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
| **Semgrep** | `pip install semgrep` | `brew install semgrep` | Static vulnerability scanning |
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

**Seucrity Note**: Email addresses are stored **Plainly** due to Cyberbot email automation system need the account email to be able to send password expiration notification, user admin access removal, ..etc..

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

# Real-Time Threat Analysis Pipeline

---

## Overview

Cyberbot's real-time threat analysis pipeline is an automated, event-driven security scanning system that activates upon detection of any file attachment or URL submitted within a monitored Discord server channel. The pipeline performs a layered, multi-engine analysis — encompassing hash signature lookups, VirusTotal multi-engine scanning, archive bomb detection, binary reverse engineering, and LLM-assisted static code analysis — before issuing a final threat verdict.

---

## Pipeline Trigger Conditions

The real-time pipeline is activated when **all** of the following conditions are satisfied:

| Condition | Requirement |
|-----------|-------------|
| **Message Author** | Must not be Cyberbot itself |
| **Channel Type** | Must not be a Direct Message channel |
| **Automation-Mode** | Must be set to `True` for the origin server |
| **Channel Exclusion** | The origin channel must not be listed in `Non-Monitor-Channels` |
| **Content** | Message must contain at least one URL or file attachment |

If `Automation-Mode` is `False`, the event is logged with a notation that automated scanning is disabled and no analysis is performed.

---

## Pipeline Architecture

```
Message Received
       │
       ▼
┌─────────────────────────────┐
│   Pre-Flight Validation     │  ── Ignore bots, DMs, excluded channels
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│   Server Config Bootstrap   │  ── Initialise server config defaults if new server
└────────────┬────────────────┘
             │
      ┌──────┴──────┐
      ▼             ▼
 URL Pipeline   File Pipeline
```

---

## Stage 1 — Pre-Flight Validation & Server Configuration Bootstrap

Before any scanning begins, Cyberbot performs the following initialization checks:

1. **Bot Self-Message Guard** — Discards any message originating from Cyberbot itself to prevent recursive processing.
2. **Direct Message Guard** — Discards messages received via Direct Message channels, which are outside the scope of server monitoring.
3. **Server Configuration Bootstrap** — If the origin server is newly detected, Cyberbot initializes its configuration defaults:
   - `Non-Monitor-Channels` → Empty exclusion list
   - `Silent-Mode` → `False` (verbose mode enabled)
   - `Automation-Mode` → `True` (real-time scanning enabled)
   - The updated configuration is persisted to `CyberBotConfig.json`.
4. **Channel Exclusion Check** — If the origin channel is present in the server's `Non-Monitor-Channels` list, the message is immediately discarded and no scanning is performed.

---

## Stage 2 — URL Scanning Pipeline

Activated when one or more URLs are detected in the message content.

### Step 2.1 — URL Extraction & Deduplication
All URLs matching the `https?://` scheme are extracted from the message content via regex pattern matching. Duplicate URLs are removed to prevent redundant scan operations.

### Step 2.2 — Path Traversal Detection
Each extracted URL is inspected for `../` sequences (URL-decoded) that may indicate a **directory traversal attack** targeting the host web server. Any URL containing such patterns is immediately flagged, the message is deleted, and the event is logged.

### Step 2.3 — URL Resolution & Accessibility Validation
Each URL is resolved and validated prior to submission to VirusTotal:

| URL Type | Handling |
|----------|----------|
| **Klipy GIF URLs** (`klipy.com/gifs/`) | Resolved to the underlying direct GIF URL via Klipy API |
| **Tenor GIF URLs** (`tenor.com/view`) | Resolved to the underlying direct GIF URL via Tenor API |
| **Standard URLs** | Validated via HTTP HEAD/GET request; URLs returning `4xx` status codes are rejected |

Unresolvable or inaccessible URLs are reported to the channel and excluded from further scanning.

### Step 2.4 — Concurrent Scan Deduplication
Before submitting a URL to VirusTotal, Cyberbot computes the SHA-256 hash of the URL and checks the `CURRENTSCANOPERATION` registry. If an identical URL is already being processed by a concurrent coroutine, the current coroutine suspends and waits for the in-progress scan to complete before proceeding.

### Step 2.5 — Local Hash Signature Lookup
The URL SHA-256 hash is cross-referenced against Cyberbot's local scan history:

- **Known Safe** → Reports the URL as previously verified safe. No VirusTotal API call is made.
- **Known Malicious** → Reports the URL as previously flagged malicious, deletes the message immediately.
- **Unknown** → Proceeds to VirusTotal submission.

### Step 2.6 — VirusTotal URL Scan
Unknown URLs are submitted to the VirusTotal API for multi-engine analysis:

- **Malicious verdict** (`malicious count > 0`) → URL is flagged, added to the local malicious hash store, and the message is deleted.
- **Clean verdict** (`malicious count = 0`) → URL is added to the local clean hash store and reported as safe.
- **Scan error** → Reported to the channel; no hash record is created.

---

## Stage 3 — File Attachment Scanning Pipeline

Activated when one or more file attachments are detected in the message. Each attachment is processed individually and sequentially through the following stages.

### Step 3.1 — Path Traversal Detection
The attachment filename is inspected for `../` sequences indicative of a **path traversal attack**. Flagged filenames result in immediate message deletion and event logging.

### Step 3.2 — File Size Validation
The attachment content length is retrieved via HTTP HEAD request. Files exceeding the **300 MB** size threshold are rejected as outside Cyberbot's supported scan size limit.

### Step 3.3 — File Download & True Format Identification
The attachment is downloaded and its **true file format** is determined by inspecting its **magic bytes** — independent of the declared file extension — to detect potential extension spoofing or format mismatch attempts. The SHA-256 hash of the raw file content is computed for subsequent lookups.

### Step 3.4 — Concurrent Scan Deduplication
Identical to Step 2.4 — the file SHA-256 hash is checked against the `CURRENTSCANOPERATION` registry to prevent duplicate concurrent scans of the same file.

### Step 3.5 — Local Hash Signature Lookup
The file SHA-256 hash is cross-referenced against Cyberbot's local scan history:

- **Known Safe** → Reports the file as previously verified safe. No further scanning is performed.
- **Known Malicious** → Reports the file as previously flagged malicious and deletes the message immediately.
- **Unknown** → Proceeds through the full scanning pipeline.

### Step 3.6 — Encrypted File Detection
Files identified as encrypted (based on true file format) are flagged as unscannnable. Cyberbot issues an advisory message recommending the recipient exercise caution, and recommends the file be re-submitted after decryption if it is intended to be legitimate.

### Step 3.7 — Format Scope Validation
Files with formats outside of Cyberbot's supported scope of analysis are reported as unscannable and excluded from further processing. Supported formats proceed to download and mount point preparation.

### Step 3.8 — VirusTotal File Scan
The downloaded file is submitted to the VirusTotal API for multi-engine file analysis. The scan result is reported in the following format:

```
<Malicious> Malicious, <Suspicious> Suspicious, <Harmless> Harmless, <Undetected> Undetected
```

- **Malicious verdict** (`malicious count > 0`) → File is flagged, added to the local malicious hash store, message is deleted, and temporary files are cleaned up.
- **Clean verdict** → Pipeline continues to archive/disk image analysis.
- **Scan error** → Noted in the log; pipeline continues.

---

## Stage 4 — Archive & Disk Image Bomb Analysis

Activated when the file is identified as an **archive or disk image format**.

### Step 4.1 — Extraction & Bomb Detection
The archive or disk image is extracted to a dedicated mount point. The extraction engine inspects for the following threat conditions:

| Threat Condition | Description | Action |
|-----------------|-------------|--------|
| **Encrypted Archive** | Archive contains encrypted content that cannot be inspected | Advisory message issued; no hash record created |
| **Path Traversal Attack** | Extracted file paths contain `../` sequences | Message deleted; flagged as malicious |
| **Archive/Disk Bomb** | Uncompressed size exceeds **32 GB** threshold | Message deleted; flagged as malicious |
| **Corrupted Disk Image** | Disk image cannot be successfully parsed or mounted | Reported to channel |
| **Recursive Archive Bomb** | More than 3 nested duplicate archive/disk files detected | Message deleted; flagged as malicious |
| **Duplicate Content Bomb** | Excessive duplicate files detected within the compressed content | Message deleted; flagged as malicious |

### Step 4.2 — Uncompressed Content Scanning
If the archive passes all bomb detection checks, its extracted contents are individually scanned:

1. The uncompressed file structure is enumerated and reported.
2. Each extracted file is hashed (SHA-256) and cross-referenced against the local hash signature store.
3. **Known Safe** files are removed from the mount point and skipped.
4. **Known Malicious** files trigger immediate parent archive deletion and pipeline termination.
5. **Unknown** files are submitted to VirusTotal for individual file analysis.

---

## Stage 5 — Executable Binary Reverse Engineering

Activated for all files identified as **compiled executable formats** within the mount point.

### Step 5.1 — Ghidra Decompilation
Each executable binary is submitted to the headless Ghidra reverse engineering engine for automated disassembly and decompilation. The decompiled output is written to a designated output file path within the mount point.

### Step 5.2 — Decompiled Output Hashing
The SHA-256 hash of each decompiled output file is computed and stored in a `CompiledHashedMap`, which maintains a mapping of `compiled binary hash → decompiled script hash`. This map is used in Stage 6 to correlate LLM analysis verdicts back to their originating binary.

---

## Stage 6 — LLM-Assisted Static Code Analysis (SCAT)

Activated for all files identified as **script file formats** within the mount point, including decompiled outputs produced in Stage 5.

### Step 6.1 — Script-to-PDF Conversion
Each script file is converted to PDF format prior to LLM submission, ensuring consistent document formatting across all supported script types.

### Step 6.2 — OpenAI GPT Static Analysis
The PDF is submitted to OpenAI GPT with a cybersecurity analyst system prompt instructing the model to assess the script for malicious patterns. The model responds with:
- `True` — Potential malware detected → File is flagged as malicious.
- `False` — No malicious patterns identified → Proceeds to Gemini analysis.

If the scan result exceeds 1,500 characters, it is delivered as a `.txt` file attachment to the Discord channel.

### Step 6.3 — Google Gemini Static Analysis
If OpenAI GPT returns a clean verdict, the PDF is submitted to Google Gemini for an independent static analysis pass under the same cybersecurity analyst role prompt. The model responds with:
- `True` — Potential malware detected → File is flagged as malicious.
- `False` — No malicious patterns identified → File is recorded as clean.

---

## Stage 7 — Final Verdict & Cleanup

### Malicious Verdict
If any stage issues a malicious verdict:
1. The SHA-256 hash of the flagged file (and its parent archive, if applicable) is recorded in the local malicious hash store.
2. The associated compiled binary hash (via `CompiledHashedMap`) is also flagged if applicable.
3. The originating Discord message is deleted.
4. The mount point and all temporary files are purged.
5. The scan session is written to `CyberbotURLAndFileScanLog.txt`.

### Clean Verdict
If all stages return a clean verdict:
1. The SHA-256 hash of the file is recorded in the local clean hash store.
2. The mount point and all temporary files are purged.
3. A safe-to-download confirmation is posted to the channel (if `Silent-Mode` is `False`).
4. The scan session is written to `CyberbotURLAndFileScanLog.txt`.

---

## Pipeline Summary

```
Message Detected
        │
        ├──► URL(s) Found
        │         │
        │         ├── Path Traversal Check
        │         ├── URL Resolution & Accessibility Validation
        │         ├── Concurrent Scan Deduplication
        │         ├── Local Hash Signature Lookup
        │         └── VirusTotal Multi-Engine URL Scan
        │
        └──► File Attachment(s) Found
                  │
                  ├── Path Traversal Check (Filename)
                  ├── File Size Validation (≤ 300 MB)
                  ├── File Download & Magic Byte Identification
                  ├── Concurrent Scan Deduplication
                  ├── Local Hash Signature Lookup
                  ├── Encrypted File Detection
                  ├── Format Scope Validation
                  ├── VirusTotal Multi-Engine File Scan
                  ├── Archive/Disk Image Bomb Detection & Extraction
                  │         └── Extracted Content → VirusTotal Scan
                  ├── Ghidra Executable Decompilation
                  └── LLM Static Code Analysis (OpenAI GPT → Google Gemini)
                            │
                            └── Final Verdict → Hash Store Update → Cleanup → Log
```

# Limitations & Future Work

---

1. If a source file token count exceeding OpenAI or Gemini context window or TPM, the content will not be analyzed by the models and given a clean verdict.

2. If you are using a free Virus Total API, then the latency of Virus Total analyses is gonna be average around **40s-80s**. The premium API would be needed, if you wish to furher extended this Discord bot into an enterprise level security tool. 

3. The pre-trained phishing email encoder-transformer were one of my ML project can be found [here](https://github.com/DavidNguyen1812/PhishingEmailDetector). I am new to machine learning, and most of the model architecture was written by Claude, under careful supervision.

4. The pre-trained password strenght encoder-transformer has the same based architecture as the phishing email. The dataset used to train the models can be found [here](https://github.com/Infinitode/PWLDS).

5. Cyberbot does not have any advance web search capability, so during the URL Resolution & Accessibility Validation phrase, if the the URL response status code are in the error range 400-500, then the URL will not be scan. Usually, a malicious website should be designed with less restriction in order to attract as much victim as possible, but that just an assumption.

6. Cyberbot can be susceptible to fileless virus, so make sure you run Cyberobt on a dedicated device like a raspberry pi, AWS EC2 instance, with a Golden Image backup.

7. The asychronous programing of Cyberbot did not integrate with semaphore to limit the number of coroutines that can access a shared resource or run a specific section of code simultaneously. This is essential to not overload the CPU with too many tasks resulting from many file/url scan operations.


