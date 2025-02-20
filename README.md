# Vanish - Filter Domains Behind CDN

Vanish is a tool written in Go that filters out domains which are protected by popular CDN/WAF providers such as Akamai, Imperva, Cloudflare, Fastly, and others. It performs DNS resolution (using `host` and `dig`) and HTTP header analysis to determine whether a domain is shielded by these services. This is especially useful when you need to avoid scanning or interacting with domains behind CDNs/WAFs.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Installing via `go install`](#installing-via-go-install)
- [Usage](#usage)
  - [Command-Line Flags](#command-line-flags)
  - [Example Commands](#example-commands)
- [How It Works](#how-it-works)
  - [DNS Checks](#dns-checks)
  - [HTTP Header Checks](#http-header-checks)
  - [Random User-Agent](#random-user-agent)
- [Output](#output)
- [Contributing](#contributing)
- [Pushing to GitHub](#pushing-to-github)
- [License](#license)
- [Contact](#contact)

---

## Features

- **CDN Detection:**  
  Vanish identifies if a domain is behind a CDN/WAF (e.g., Akamai, Imperva, Cloudflare, Fastly, etc.) by analyzing both DNS records and HTTP response headers.
  
- **Randomized User-Agent:**  
  Each HTTP request uses a randomly selected User-Agent from a predefined list to help avoid trivial blocking.

- **Parallel Processing:**  
  Utilizes goroutines for concurrent processing, which improves efficiency when scanning large domain lists.

- **Verbose Mode:**  
  When enabled, Vanish outputs detailed messages indicating where and how a CDN/WAF was detected.

- **Flexible Input Options:**  
  Accepts a single domain, a file containing multiple domains, or domains provided via standard input (stdin).

---

## Installation

### Prerequisites

- **Go** (version 1.18 or later is recommended)
- **DNS Tools:**  
  Ensure that the `host` and `dig` commands are installed on your system.
  - On Debian/Ubuntu, you can install them with:
    ```bash
    sudo apt-get install dnsutils
    ```
  - On CentOS/Fedora, you can install them with:
    ```bash
    sudo yum install bind-utils
    ```

### Building from Source

1. **Clone the Repository**

   Clone the repository to a folder outside your `$GOPATH` (this is recommended):
   ```bash
   git clone https://github.com/yourusername/vanish.git
   cd vanish
   ```
   Replace `yourusername` with your actual GitHub username.

2. **Initialize the Go Module**

   Initialize the module by providing a valid module path:
   ```bash
   go mod init github.com/yourusername/vanish
   ```

3. **Download Dependencies and Build**

   Run the following commands:
   ```bash
   go mod tidy
   go build -o vanish main.go
   ```
   This produces an executable named `vanish`.

### Installing via `go install`

If your repository is public (or you have access to the module path), you can install Vanish directly into your `$GOPATH/bin` (or `$GOBIN`):

```bash
go install github.com/yourusername/vanish@latest
```
Replace `github.com/yourusername/vanish` with your repository path. Make sure your Go binary directory is in your `PATH`.

---

## Usage

Vanish accepts several command-line flags to control its behavior.

### Command-Line Flags

| Flag                | Description                                                                                     |
|---------------------|-------------------------------------------------------------------------------------------------|
| `-t <domain>`       | Specify a **single domain** to check.                                                           |
| `-l <file>`         | Provide a file containing a list of domains (one per line).                                      |
| `-c <number>`       | Set the number of concurrent goroutines for parallel processing (default: 10).                   |
| `-v`                | Enable **verbose mode**. Outputs detailed CDN/WAF detection messages as they occur.             |
| `-h`                | Show help message.                                                                              |

### Example Commands

1. **Check a Single Domain:**
   ```bash
   ./vanish -t example.com
   ```

2. **Check Domains from a File:**
   ```bash
   ./vanish -l domains.txt
   ```

3. **Check Domains via Standard Input:**
   ```bash
   cat domains.txt | ./vanish
   ```

4. **Verbose Mode (Show Detection Details):**
   ```bash
   ./vanish -l domains.txt -v
   ```

5. **Increase Concurrency:**
   ```bash
   ./vanish -l domains.txt -c 20
   ```

---

## How It Works

### DNS Checks

- **Process:**  
  Vanish executes the `host` and `dig` commands for each domain.
  
- **Detection:**  
  It scans the output for known CDN/WAF keywords such as `akamai`, `imperva`, `cloudflare`, `fastly`, etc.  
  - If a match is found, the domain is marked as being behind a CDN/WAF.
  - In verbose mode, a message is printed showing the detection source (e.g., DNS `host` or `dig`).

### HTTP Header Checks

- **Process:**  
  For domains that pass the DNS checks, an HTTP request is made to the domain.
  
- **Detection:**  
  The HTTP response headers, particularly `Server` and `X-CDN`, are inspected for names of CDN/WAF providers.
  - If a provider is detected, the domain is filtered out.
  - Verbose mode outputs detection details (e.g., "CDN detected via HTTP: Akamai").

### Random User-Agent

- **Purpose:**  
  Each HTTP request uses a randomly chosen User-Agent string from a predefined list to reduce the likelihood of trivial blocking.

---

## Output

- **Default Behavior:**  
  Only domains that are **not** detected as being behind a CDN/WAF are printed to standard output.

- **Verbose Mode (`-v`):**  
  In addition to printing clean domains, detection messages are displayed in real time for domains that are filtered out. For example:
  ```
  example.com (CDN detected via DNS 'host': Cloudflare)
  example.net (CDN detected via HTTP: Akamai)
  example.org
  testsite.com
  ```

---

## Contributing

Contributions to Vanish are welcome!

1. **Fork the Repository** on GitHub.
2. **Clone Your Fork:**
   ```bash
   git clone https://github.com/yourusername/vanish.git
   ```
3. **Create a New Branch:**
   ```bash
   git checkout -b my-feature-branch
   ```
4. **Make Your Changes and Commit:**
   ```bash
   git add .
   git commit -m "Describe your changes"
   ```
5. **Push Your Changes:**
   ```bash
   git push origin my-feature-branch
   ```
6. **Open a Pull Request** on GitHub.

---

## Pushing to GitHub

If you’re starting a new repository for Vanish, follow these steps:

1. **Create a New Repository** on GitHub (e.g., `github.com/yourusername/vanish`).
2. **Initialize a Local Git Repository:**
   ```bash
   git init
   git remote add origin https://github.com/yourusername/vanish.git
   ```
3. **Add Files and Commit:**
   ```bash
   git add .
   git commit -m "Initial commit"
   ```
4. **Push to GitHub:**
   ```bash
   git push -u origin main
   ```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

For questions, issues, or suggestions:

- **GitHub Issues:** [Open an Issue](https://github.com/yourusername/vanish/issues)
- **Email:** *(Include your contact email if desired)*

---

Enjoy using **Vanish** to filter out domains behind major CDN/WAF providers!
