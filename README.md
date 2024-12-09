# Cercle

## Overview

Cercle is a powerful command-line tool for analyzing SSL/TLS certificates. It is designed to assist security professionals, developers, and system administrators in evaluating the security and validity of SSL certificates efficiently.

## Features

- Analyze SSL/TLS certificates of any website.
- Check certificates on custom ports.
- Generate outputs in JSON or YAML formats.

## Installation

### Prerequisites

- **Go**: Version 1.23 or later is required. Ensure Go is installed and configured correctly on your system.

### Steps to Install

To install Cercle, run the following command:

```bash
go install github.com/ezrantn/cercle@latest
```

After installation, verify it by checking the version:

```bash
cercle version
```

## Usage

### Basic Commands

Check a Website's SSL Certificate

```bash
cercle google.com
```

Check SSL Certificate on a Specific Port

```bash
cercle google.com -p 8443
```

### Output Formats

You can customize the output format for better integration with other tools.

**JSON Output**

```bash
cercle google.com --output <yourfile>.json
```

**YAML Output**

```bash
cercle google.com --output <yourfile>.yaml
```

## License

This tool is open-source and available under the [MIT](https://github.com/ezrantn/cercle/blob/main/LICENSE) License.

## Contributions

Contributions are welcome! Please feel free to submit a pull request.
