# GitBlast
<p align="center">
  <img src="gitblast.png" width="100%" alt="GitBlast Banner">
</p>

**GitBlast**  
A powerful tool that automates extensive GitHub searches using 23 predefined dorks and regex patterns, with optional entropy detection, built for speed and scale, aimed at security researchers, developers, and organizations.

## Features
- **Broad search**: Leverages over 20 dorks to uncover a wide spectrum of references.
- **Secret detection**: Scans for API keys, tokens, passwords, and more via robust regex.
- **Entropy boost**: Optionally flags high-entropy strings likely to be sensitive.
- **API integration**: Uses GitHub’s REST API with retries and rate-limit handling.
- **Flexible output**: Write results to console or a specified file for later review.
- **Lightweight**: Minimal dependencies; easy to clone and run anywhere.

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/5u5urrus/gitblast.git
   ```
2. **Install Python 3.6+ and Requests**:
   ```bash
   cd gitblast
   pip install requests
   ```
3. **Obtain a GitHub token** (Personal Access Token):
   - Generate at [GitHub Token Settings](https://github.com/settings/tokens)
   - Copy and keep it secure.

## Usage

### Basic Command
```bash
python gitblast.py "mycompany.com" GITHUB_TOKEN
```
Runs a thorough scan for “mycompany.com” references, printing results to console.

### Save to File
```bash
python gitblast.py "mycompany.com" GITHUB_TOKEN output.txt
```
Saves output to `output.txt` while also printing to console.

### Enable Entropy Detection
```bash
python gitblast.py "mycompany.com" GITHUB_TOKEN output.txt --entropy
```
Flags high-entropy strings in addition to pattern-based detection.

### Full Syntax
```bash
python gitblast.py <keyword> <github_token> [output_file] [--entropy]
```
- `<keyword>`: The term or domain to search for  
- `<github_token>`: Your GitHub Personal Access Token  
- `[output_file]`: Optional. If provided, saves results here  
- `[--entropy]`: Optional. Enables entropy-based scanning

## Examples

### Basic Scan
```bash
python gitblast.py "hacking.cool" "ghp_yourtoken123"
```
**Sample Output**:
```
[*] Searching GitHub for secrets related to: hacking.cool

[+] Dork Query: 'hacking.cool'
    Found 13 results.
   -> Checking ...
      No secrets detected in file.
...
No secrets detected across all dorks.
Done.
```

### Entropy Scan
```bash
python gitblast.py "hacking.cool" "ghp_yourtoken123" results.txt --entropy
```
**Sample Output**:
```
[*] Searching GitHub for secrets related to: hacking.cool
[*] Entropy-based detection is ENABLED

[+] Dork Query: 'hacking.cool'
    Found 13 results.
   -> Checking ...
      [SECRET FOUND]
         => [ENTROPY] High entropy value in line 27: passkey=sdf9282...
...

Results saved to results.txt
```

## Configuration
In **gitblast.py**, you can tweak:
- **DORK_QUERIES**: The list of 23 dorks to be used in searches.
- **SECRET_PATTERNS**: Regex patterns for detecting secrets.
- **MAX_PAGES**: How many pages of GitHub results to fetch per dork.
- **ENTROPY_THRESHOLD**: Adjust Shannon entropy sensitivity.

## Requirements
- **Python 3.6+**  
- **Requests library** (installed via pip)  
- **GitHub token** with “public_repo” or relevant scopes

## Contributing
1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YourUserName/gitblast.git
   ```
3. **Create** a new branch for your feature or fix:
   ```bash
   git checkout -b feature-xyz
   ```
4. **Commit** and **push** changes:
   ```bash
   git add .
   git commit -m "Add awesome feature"
   git push origin feature-xyz
   ```
5. **Open a Pull Request** from your branch into the main repo.

## License
Licensed under the [MIT License](https://choosealicense.com/licenses/mit/).

## Author
Created by [Vahe Demirkhanyan](mailto:vdemirkhanyan@yahoo.ca)

<p align="center">
  <strong>Blast away secrets with GitBlast - because exposure isn’t an option.</strong>
</p>
