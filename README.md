# Cyberbot Overview
A security scanner designed for continuous, automated threat monitoring across Discord servers — detecting malicious file attachments and URLs in real time.
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
├── CycberbotGhidraProject
├── DownloadDirectory
├── Files
│   ├── Configurations
│   │   ├── CyberBotConfig.json
│   │   └── OneTimeResetPasswordToken.json
│   ├── HashedSignatures
│   │   ├── CleanSHA256Signatures.json
│   │   └── MaliciousSHA256Signatures.json
│   ├── LLM Usages
│   │   ├── LLMMonthlyUsage.csv
│   │   └── LLMYearlyUsage.csv
│   ├── Logs
│   │   ├── CyberBotCronTaskLog.txt
│   │   ├── CyberBotDiscordCommandsLog.txt
│   │   ├── CyberbotURLAndFileScanLog.txt
│   │   └── OpenAIandGeminiSCATResults.txt
│   ├── MLModels
│   │   ├── CPU
│   │   └── MPS
├── PythonScripts
    ├── GhidraDecompileScript
    │   └── GhidraDecompile.py
    ├── Cyberbot.py
    ├── EncoderTransformers.py
    └── env
