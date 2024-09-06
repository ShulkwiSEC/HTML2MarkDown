# HTML to Markdown Converter

## Overview

The HTML to Markdown Converter tool (`Html2Markdown.py`) is designed to streamline the conversion of HTML content into Markdown format, saving you time and effort.

## Features

- **URL Input**: Fetch HTML content directly from a remote URL.
- **Local File Input**: Convert HTML files from your local filesystem.
- **Output Path**: Specify the destination for the converted Markdown file.

## Usage

### Command-Line Options

- `--url <URL>`: Fetch HTML content from a remote URL.
- `--local <path>`: Read HTML content from a local file.
- `--output <path>`: Define the output path for the converted Markdown file.

### Example

To convert HTML content from a URL to a Markdown file, use the following command:

```bash
python3 Html2Markdown.py --url http://www.example.com/blog/how-i-heat-myself --output README.md
