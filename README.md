# YayPDF

YayPDF is a powerful Python CLI tool designed to crawl websites and download all discovered PDF files. It supports recursive crawling, multi-threaded downloading, and custom HTTP headers for authenticated sessions.

## Features

- **Recursive Crawling**: Crawl through pages to find PDFs at a specified depth.
- **Concurrency**: fast multi-threaded downloading.
- **Smart Filtering**: Options to restrict downloads to the same domain and verify content types.
- **Custom Headers**: Support for Cookies and Authorization headers for protected content.
- **Polite Crawling**: Configurable delay between requests to respect server limits.

## Installation

Ensure you have Python 3 installed. Then install the required dependencies:

```bash
pip install requests beautifulsoup4
```

## Usage

Basic usage:

```bash
python app.py "https://example.com/resources"
```

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `url` | Starting page URL | (Required) |
| `--out` | Output directory for PDFs | `downloaded_pdfs` |
| `--depth` | Crawl depth (0 = only the starting page) | `0` |
| `--same-domain` | Restrict crawling/downloading to the starting domain | `False` |
| `--concurrency` | Number of parallel downloads | `6` |
| `--delay` | Delay between page fetches (seconds) | `0.0` |
| `--header` | Add custom HTTP header (repeatable) | `[]` |

## Examples

### 1. Simple Download
Download all PDFs from a single page into the `pdfs` folder:

```bash
python app.py "https://example.com/books" --out pdfs
```

### 2. Recursive Crawl
Crawl the starting page and links found on it (depth 1), downloading only from the same domain:

```bash
python app.py "https://university.edu/papers" --depth 1 --same-domain
```

### 3. Authenticated & Polite
Download from a site requiring login cookies, with a 1-second delay between requests to be polite:

```bash
python app.py "https://site.com/protected" \
  --delay 1.0 \
  --header "Cookie: session_id=12345" \
  --header "User-Agent: MyCustomCrawler"
```

## License

This project is licensed under the terms of the included LICENSE file.
