# Cyberbot Overview

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

```
├── CycberbotGhidraProject                        # Dedicated directory for Cyberbot to create temporary Ghidra Project during static disassembly and decompilation process
├── DownloadDirectory                             # Dedicated directory for Cyberbot to temporary store file for analysis
├── Files                                        
│   ├── Configurations
│   │   ├── CyberBotConfig.json                   # Cyberbot Configuration to securely store user admin account authentication and Discord server admin acess, chat channels in server that Cyberbot not authorized to monitor, and scanning functionality
│   │   └── OneTimeResetPasswordToken.json        # Temporary stored a user requested password reset token
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

| Application Command | Purpose | Who Can Execute | Restrictions |
|---|---|---|---|
| `/create_admin_account` | Registers a new administrator account with Cyberbot, requiring a valid email address for identity verification and registration confirmation | Any server member | Each administrator account is uniquely bound to a single user and email address |
| `/admin_log_in` | Initiates an authenticated 1-hour administrative session, granting access to Cyberbot's server configuration and management controls | Any user with a registered administrator account | Requires administrator access privileges authorized by the server owner |
| `/admin_log_out` | Terminates the current active administrative session | Any user with a registered administrator account | The user must hold server owner-authorized administrator privileges and have an active open session |
| `/request_password_reset_token` | Requests a time-limited (3-minute) password reset token delivered to the account's registered email address | Any user with a registered administrator account | Token issuance is blocked if the account password has not satisfied the minimum password age policy of 3 hours, or if the account is currently locked |
| `/change_password` | Updates the administrator account credentials | Any user with a registered administrator account | Requires a valid password reset token for identity verification prior to any credential change |
| `/adding_admins` | Grants a server member administrative access, enabling them to view and modify Cyberbot's server configuration settings | Server Owner only | The designated server member must have an existing registered administrator account |
| `/removing_admins` | Revokes a server member's administrative access privileges | Server Owner only | The designated server member must currently hold active administrative access |
| `/viewing_cyberbot_configuration` | Retrieves and displays the current Cyberbot server configuration settings in read-only mode | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/cyberbot_config` | Modifies and applies changes to the current Cyberbot server configuration settings | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/non_monitoring_channel` | Adds or removes the current channel from Cyberbot's real-time monitoring exclusion list | Any user with a registered administrator account | Requires server owner-authorized administrator privileges |
| `/get_list_of_accessible_servers` | Viewing all the server that the user has admin access | Any user with a registered administrator account | N/A |
| `/semgrep_vulnerability_scan` | Vulnerability scanning Semgrepo | Any server member | N/A |
| `/phishing_email_scan` | Initiating pre-trained encoder transformers for phishing content detection | Any server member | N/A |
| `/manual_malware_scan` | Analyzing a file for any malicious attributes | Any server member | N/A |
| `/list_supported_formats` | Displaying all file formats and categories that Cyberbot can scan | Any server member | N/A |
| `/checking_file_true_format` | Checking the file true extension by it magic bytes | Any server member | N/A |










