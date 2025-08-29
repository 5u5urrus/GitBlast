# GitBlast - GitHub Secret Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/5u5urrus/gitblast)](https://github.com/5u5urrus/gitblast/issues)

<p align="center">
  <img src="gitblast.png" width="100%" alt="GitBlast Banner">
</p>

GitBlast is an advanced GitHub repository scanner that automatically searches for exposed secrets, API keys, tokens, and other sensitive data across public repositories using multiple detection methods and comprehensive search strategies.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Search Strategies](#search-strategies)
- [Detection Methods](#detection-methods)
- [Command Reference](#command-reference)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Responsible Use](#responsible-use)
- [Author](#author)

## Features

- **Comprehensive Search Coverage**: 23+ predefined search dorks targeting different file types and contexts
- **Multi-Method Detection**: Regex pattern matching combined with Shannon entropy analysis
- **Advanced Secret Recognition**: Detects AWS keys, GitHub tokens, API keys, private keys, database credentials, and more
- **Rate Limit Management**: Built-in token bucket system respects GitHub API limits
- **Concurrent Processing**: Multi-threaded file analysis with configurable worker pools
- **False Positive Reduction**: Context-aware filtering and provider-specific validation
- **Flexible Output**: Console, file, and JSON output formats
- **CI/CD Integration**: Machine-readable output and exit codes for automated pipelines

## Installation

### Prerequisites
- Python 3.6 or higher
- GitHub Personal Access Token
- Internet connection for API access

### Install Dependencies
```bash
git clone https://github.com/5u5urrus/gitblast.git
cd gitblast
pip install requests
```

### GitHub Token Setup
1. Visit [GitHub Personal Access Tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Select scopes: `public_repo` (minimum required)
4. Copy the generated token and keep it secure

## Quick Start

### Basic Scan
```bash
python gitblast.py "mycompany" your_github_token_here
```

### Save Results to File
```bash
python gitblast.py "mycompany" your_github_token_here results.txt
```

### Enable Entropy Detection
```bash
python gitblast.py "mycompany" your_github_token_here results.txt --entropy
```

## Search Strategies

GitBlast employs 23 specialized search dorks to maximize coverage across different contexts:

### Core Searches
- `{keyword}` - Direct keyword matching
- `{keyword} filename:.env password` - Environment files with passwords
- `{keyword} filename:config password` - Configuration files
- `{keyword} filename:settings password` - Application settings
- `{keyword} filename:credentials` - Credential files

### Cloud Provider Specific
- `{keyword} AWS_SECRET_ACCESS_KEY` - AWS credentials
- `{keyword} filename:dockercfg auth` - Docker registry credentials
- `{keyword} filename:npmrc _auth` - NPM authentication tokens

### Cryptographic Materials
- `{keyword} "BEGIN RSA PRIVATE KEY"` - Private SSH/SSL keys
- `{keyword} filename:id_rsa` - SSH private keys
- `{keyword} filename:key.pem` - PEM certificate files

### API & Service Tokens
- `{keyword} "api_key"` - Generic API keys
- `{keyword} TOKEN` - Token references
- `{keyword} SECRET` - Secret references

### Database & Connection Strings
- `{keyword} "db_password"` - Database passwords
- `{keyword} "db_username"` - Database usernames
- `{keyword} "database_url"` - Database connection URLs
- `{keyword} "connectionstring"` - Connection strings

### File Type Searches
- `{keyword} extension:yaml password` - YAML configuration files
- `{keyword} extension:json password` - JSON configuration files
- `{keyword} extension:xml password` - XML configuration files
- `{keyword} filename:htpasswd` - Apache password files
- `{keyword} filename:properties password` - Java properties files

### Noise Reduction Qualifiers
All searches include filters to reduce false positives:
```
in:file size:<20000 
-extension:md -filename:README -filename:CHANGELOG -filename:LICENSE
-path:tests -path:test -path:examples -path:example -path:samples -path:sample
-path:docs -path:.github -path:.git
```

## Detection Methods

### Pattern-Based Detection
GitBlast uses regex patterns to identify known secret formats:

#### Cloud Provider Secrets
- **AWS Access Keys**: `AKIA[0-9A-Z]{16}` and `ASIA[0-9A-Z]{16}`
- **AWS Secret Keys**: 40-character base64 strings in AWS context
- **Google API Keys**: `AIza[0-9A-Za-z\-_]{35}`

#### Version Control Tokens
- **GitHub Personal Access**: `ghp_[A-Za-z0-9]{36}`
- **GitHub App Tokens**: `github_pat_[A-Za-z0-9_]{82}`
- **GitHub OAuth**: `gho_`, `ghu_`, `ghs_`, `ghr_` variants

#### Payment & Communication
- **Stripe Keys**: `sk_live_` and `sk_test_` prefixed tokens
- **Square Tokens**: `sq0csp-` prefixed tokens
- **Slack Tokens**: `xox[baprs]-` formatted tokens
- **Discord Webhooks**: Discord webhook URLs
- **Twilio Credentials**: Account SIDs and Auth tokens

#### Generic Patterns
- **JWT Tokens**: Base64-encoded JSON Web Tokens with header validation
- **Private Keys**: PEM-formatted private keys
- **Credit Cards**: Luhn algorithm validated card numbers
- **Connection Strings**: Database and service connection strings

### Entropy-Based Detection
When enabled with `--entropy`, GitBlast analyzes strings for high randomness:

- **Shannon Entropy Calculation**: Measures randomness in character distribution
- **Threshold-Based Filtering**: Configurable entropy threshold (default: 4.3)
- **Context Awareness**: Higher sensitivity for key-value pairs with suspicious key names
- **Length Requirements**: Minimum length requirements prevent false positives

### Validation & Filtering
- **Provider Validation**: Format-specific validation (e.g., Luhn algorithm for credit cards)
- **False Positive Reduction**: Filters test data, examples, and placeholder values
- **Comment Detection**: Ignores secrets in code comments
- **Context Analysis**: Considers surrounding code context

## Command Reference

```bash
python gitblast.py <keyword> <github_token> [output_file] [options]
```

### Required Arguments
- `keyword` - Search term (company name, domain, repository, etc.)
- `github_token` - GitHub Personal Access Token

### Optional Arguments
- `output_file` - File path to save results (optional, outputs to console if not specified)

### Options
| Flag | Description | Default |
|------|-------------|---------|
| `--entropy` | Enable entropy-based detection | Disabled |
| `--max-pages` | Maximum search result pages per dork | 3 |
| `--per-page` | Results per page (GitHub API limit: 100) | 30 |
| `--threads` | Concurrent file processing workers | 6 |
| `--raw-rps` | Rate limit for raw file requests (per second) | 4.0 |
| `--json` | Output results in JSON format | Disabled |
| `--fail-on-findings` | Exit with code 2 if secrets found (CI/CD) | Disabled |

### Examples

#### Basic Organization Scan
```bash
python gitblast.py "mycompany" ghp_abcd1234... 
```

#### High-Throughput Scan
```bash
python gitblast.py "target" ghp_token123 results.txt --max-pages 5 --threads 10 --raw-rps 8
```

#### CI/CD Integration
```bash
python gitblast.py "myorg" $GITHUB_TOKEN scan_results.json --json --fail-on-findings
```

#### Comprehensive Scan with Entropy
```bash
python gitblast.py "company.com" ghp_xyz789 full_scan.txt --entropy --max-pages 10
```

## Output Formats

### Console Output
```
[*] Searching GitHub for secrets related to: mycompany
[*] Entropy-based detection is DISABLED
[*] Concurrency: threads=6, raw_rps=4.0

[+] Dork Query: 'mycompany filename:.env password'
    Found 15 results.
   -> Checking mycompany/webapp / config/.env
      https://github.com/mycompany/webapp/blob/main/config/.env
      [SECRET FOUND]
         => [PATTERN:AWS_SECRET_ACCESS_KEY] config/.env:12  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
            export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### JSON Output
```json
[
  {
    "repo": "mycompany/webapp",
    "path": "config/.env",
    "url": "https://github.com/mycompany/webapp/blob/main/config/.env",
    "matches": [
      {
        "type": "PATTERN",
        "rule": "AWS_SECRET_ACCESS_KEY",
        "line": 12,
        "preview": "wJalrX…PLEKEY"
      }
    ]
  }
]
```

### File Output
Results are saved to the specified file in the same format as console output, allowing for later analysis and reporting.

## Configuration

### Environment Variables
```bash
export GITHUB_TOKEN="your_token_here"
python gitblast.py "target" $GITHUB_TOKEN
```

### Customizing Search Patterns
Edit the `SECRET_PATTERNS` list in `gitblast.py` to add custom regex patterns:

```python
SECRET_PATTERNS.append(("CUSTOM_API_KEY", re.compile(r'myapi_[a-f0-9]{32}')))
```

### Adjusting Entropy Sensitivity
Modify the `ENTROPY_THRESHOLD` constant (default: 4.3):
- Lower values: More sensitive, more false positives
- Higher values: Less sensitive, might miss some secrets

## Performance Tuning

### Rate Limiting
- **API Requests**: GitHub enforces 30 requests/minute for search API
- **Raw File Requests**: Configurable via `--raw-rps` (default: 4/second)
- **Concurrent Workers**: Balance between `--threads` and rate limits

### Memory Usage
- Large repositories with many files can consume significant memory
- Consider reducing `--max-pages` or `--per-page` for memory-constrained environments
- Files larger than 1MB are automatically skipped

### Network Optimization
- Use persistent connections (automatically handled)
- Implement retry logic with exponential backoff
- Connection pooling for improved performance

## Troubleshooting

### Common Issues

#### Rate Limit Errors
```
[!] Error: HTTP 429 - rate limit exceeded
```
**Solution**: Reduce `--raw-rps` value or wait for rate limit reset

#### Token Permission Errors
```
[!] Error: HTTP 403 - Bad credentials
```
**Solution**: Verify token has `public_repo` scope

#### No Results Found
**Potential Causes**:
- Target keyword too specific or uncommon
- All matching repositories are private
- Search filters too restrictive

#### Memory Issues
**Solution**: Reduce concurrent workers with `--threads` parameter

### Performance Optimization
- Start with conservative settings (`--threads 3 --raw-rps 2`)
- Gradually increase based on your network and GitHub API limits
- Monitor output for rate limiting messages

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Responsible Use

**IMPORTANT NOTICE**: This tool is designed for legitimate security research, compliance auditing, and protecting your own organization's repositories. Users must:

- Only scan repositories you own or have explicit permission to test
- Respect GitHub's Terms of Service and API usage guidelines  
- Follow responsible disclosure practices when finding vulnerabilities
- Not use this tool for malicious purposes or unauthorized access attempts
- Comply with all applicable laws and regulations in your jurisdiction

The authors assume no responsibility for misuse of this software. Use at your own risk and ensure you have proper authorization before scanning any repositories.

## Author
Created by [Vahe Demirkhanyan](mailto:vahe@hackvector.io)
