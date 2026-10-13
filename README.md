# SecretSweep

**Lightweight, Local-First Secret Scanner**

SecretSweep is a command-line security tool written in Python that scans files and directories for potentially exposed secrets, API keys, authentication tokens, private key blocks, and sensitive credential files.

It helps developers identify accidental credential exposure during security reviews and before committing code to version control.

## Features

- **Secret Detection:** Identifies patterns associated with AWS, GitHub, Slack, Google, Stripe, OpenAI-style, and Anthropic credentials.
- **JWT Detection:** Detects JSON Web Token patterns.
- **Private Key Detection:** Identifies private key blocks and potentially sensitive key files.
- **Credential Leak Detection:** Searches for hardcoded passwords, tokens, API keys, and credentials embedded in URLs.
- **Sensitive File Discovery:** Flags files such as `.env`, private keys, credential files, and Terraform state files.
- **Redacted Findings:** Masks detected secret values in scan results.
- **Flexible Scanning:** Supports custom paths, directory exclusions, and configurable file-size limits.
- **Multiple Output Formats:** Displays readable terminal output or generates JSON reports.
- **CI/CD Integration:** Provides meaningful exit codes for automated security checks.
- **Ignore Support:** Allows individual lines to be skipped using `secretsweep:ignore`.

## Requirements

- Python 3.8 or later
- No third-party dependencies required

## Installation

Clone the repository:

```bash
git clone https://github.com/2987blade/secretsweep.git
cd secretsweep
```

No additional package installation is required.

## Usage

Scan the current directory:

```bash
python3 secretsweep.py
```

Scan a specific directory or file:

```bash
python3 secretsweep.py /path/to/project
```

Scan multiple paths:

```bash
python3 secretsweep.py src config.py
```

Generate JSON output:

```bash
python3 secretsweep.py . --json
```

Save the report to a file:

```bash
python3 secretsweep.py . -o report.txt
```

Exclude additional directories:

```bash
python3 secretsweep.py . --exclude tests docs
```

Set the maximum file size to 2 MB:

```bash
python3 secretsweep.py . --max-size 2048
```

Always return exit code `0`, even when findings exist:

```bash
python3 secretsweep.py . --no-fail
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings, or `--no-fail` is enabled |
| `1` | Potential secrets detected |
| `2` | Invalid input path or another reported input error |

## How It Works

1. Traverses the specified files and directories.
2. Skips configured directories, selected file extensions, binary files, and oversized files.
3. Applies regular-expression patterns to identify potential secrets.
4. Checks for sensitive filenames and filters certain placeholder values.
5. Redacts detected values and reports their file paths and line numbers.
6. Outputs results in readable text or JSON.

## Limitations

- Detection relies on predefined patterns and may produce false positives or miss unsupported secret formats.
- Findings require manual verification; the tool does not validate whether credentials are active.
- Secret detection is not a replacement for comprehensive secret scanning or a full security audit.
- Removing a credential from the current file does not remove it from Git history.

## Security Best Practices

If a genuine secret is discovered:

1. Revoke or rotate the exposed credential immediately.
2. Remove it from the source code and use environment variables or a secrets manager.
3. Review Git history and repository exposure.
4. Investigate potential unauthorized access.

## Disclaimer

SecretSweep is intended for authorized security reviews and defensive development workflows. Only scan repositories and files you own or have explicit permission to assess.
