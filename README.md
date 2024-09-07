
# Vanish - Filter Domains Behind CDN

`Vanish` is a tool that filters out domains that are behind CDNs such as Akamai, Imperva, and Cloudflare by checking DNS resolution and HTTP headers. This tool is particularly useful when you want to avoid scanning or interacting with domains that are protected by CDNs.

## Features

- **CDN Detection:** Detects if a domain is using CDNs such as Akamai, Imperva, or Cloudflare via DNS or HTTP headers.
- **Randomized User-Agent:** Uses a randomly generated User-Agent for each HTTP request to avoid detection.
- **Parallel Processing:** Supports multi-threading to process multiple domains in parallel.
- **Verbose Mode:** Provides detailed information about CDN detection when enabled.
- **Flexible Input Options:** Can accept a single domain, a list of domains from a file, or a list of domains via stdin.

## Installation

### Prerequisites

Before using the script, ensure you have the following installed:

- **Python 3.x**
- **Required Python Packages:**
  - `requests`
  - `fake_useragent`
  
You can install the required packages using `pip`:

```bash
pip install requests fake_useragent
```

## Usage

Vanish can be used with different options for processing single or multiple domains.

### Command-Line Options

- `-l`, `--list`: File containing a list of domains to check.
- `-t`, `--target`: Specify a single domain to check.
- `-c`, `--concurrence`: Number of threads for parallel execution (default: 10).
- `-v`, `--verbose`: Enable verbose mode to show CDN detection details.

### Example Usage

1. **Check a single domain:**

   ```bash
   python vanish.py -t example.com
   ```

2. **Check a list of domains from a file:**

   ```bash
   python vanish.py -l domains.txt
   ```

3. **Check domains from stdin:**

   ```bash
   cat domains.txt | python vanish.py
   ```

4. **Enable verbose mode to show CDN detection details:**

   ```bash
   python vanish.py -t example.com -v
   ```

5. **Run with multiple threads for faster processing:**

   ```bash
   python vanish.py -l domains.txt -c 20
   ```

## How It Works

### DNS Check

The tool uses the `host` command to check DNS resolution. If the DNS output contains references to CDN providers such as Akamai, Imperva, or Cloudflare, the domain is filtered out.

### HTTP Headers Check

If the domain passes the DNS check, the tool makes an HTTP request to the domain and checks the `Server` and `X-CDN` headers to identify any CDN provider. If a CDN is detected, the domain is filtered out.

### Random User-Agent

To avoid detection or blocking, the tool uses a random User-Agent for each HTTP request, which is generated using the `fake_useragent` library.

## Output

The tool prints out the domains that are **not** behind a CDN. Domains behind a CDN will be filtered out and will not appear in the output unless verbose mode is enabled.

## Contact

For any questions or feedback, feel free to reach out via email or open an issue on GitHub.
