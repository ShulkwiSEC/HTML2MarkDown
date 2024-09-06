# HTML to Markdown Converter

## Overview

The HTML to Markdown Converter tool (`Html2Markdown.py`) is designed to streamline the conversion of HTML content into Markdown format, saving you time and effort.

## Features

- **URL Input**: Fetch HTML content directly from a remote URL.
- **Local File Input**: Convert HTML files from your local filesystem.
- **Output Path**: Specify the destination for the converted Markdown file.

## Usage

### Command-Line Options

  ``` -h, --help ```       show this help message and exit
  ``` --url URL ```        URL to fetch HTML from.
  ``` --local LOCAL ```   Path to the local HTML file.
  ``` --output OUTPUT ```  Path to the output Markdown file. If not provided, the output will be printed to the console.
  ``` --ignore-media ```   Ignore media content (images, videos) in the Markdown output.

### Example

To convert HTML content from a URL to a Markdown file, use the following command:

```bash
python3 Html2Markdown.py --url http://www.example.com/blog/how-i-heat-myself --output README.md --ignore-media