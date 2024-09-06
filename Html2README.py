import argparse
import requests
from bs4 import BeautifulSoup
import html2text

class HtmlToMarkdownConverter:
    def __init__(self, input_source, output_file=None, ignore_media=False):
        self.input_source = input_source
        self.output_file = output_file
        self.ignore_media = ignore_media

    def fetch_html_from_url(self):
        try:
            response = requests.get(self.input_source)
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response.text
        except requests.RequestException as e:
            print(f"Error fetching HTML from URL: {e}")
            return None

    def read_html_from_file(self):
        try:
            with open(self.input_source, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            print(f"File not found: {self.input_source}")
            return None
        except IOError as e:
            print(f"Error reading file: {e}")
            return None

    def remove_head_and_social_links(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')

        # Remove <head> content
        for head in soup.find_all('head'):
            head.decompose()

        # Remove social media links
        social_media_domains = [
            'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'pinterest.com', 'youtube.com', 'tiktok.com', 'snapchat.com'
        ]
        for a in soup.find_all('a', href=True):
            if any(domain in a['href'] for domain in social_media_domains):
                a.decompose()

        return str(soup)

    def convert_html_to_md(self, html_content):
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = self.ignore_media
        return h.handle(html_content)

    def save_markdown_file(self, markdown_content):
        try:
            with open(self.output_file, 'w', encoding='utf-8') as file:
                file.write(markdown_content)
            print(f"Conversion complete. Markdown file saved as {self.output_file}")
        except IOError as e:
            print(f"Error writing file: {e}")

    def print_markdown(self, markdown_content):
        print(markdown_content)

    def process(self):
        if self.input_source.startswith('http://') or self.input_source.startswith('https://'):
            html_content = self.fetch_html_from_url()
        else:
            html_content = self.read_html_from_file()

        if html_content:
            cleaned_html = self.remove_head_and_social_links(html_content)
            markdown_content = self.convert_html_to_md(cleaned_html)
            if self.output_file:
                self.save_markdown_file(markdown_content)
            else:
                self.print_markdown(markdown_content)
        else:
            print("Failed to retrieve or read HTML content.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert HTML to Markdown.')
    parser.add_argument('--url', type=str, help='URL to fetch HTML from.')
    parser.add_argument('--local', type=str, help='Path to the local HTML file.')
    parser.add_argument('--output', type=str, help='Path to the output Markdown file. If not provided, the output will be printed to the console.')
    parser.add_argument('--ignore-media', action='store_true', help='Ignore media content (images, videos) in the Markdown output.')

    args = parser.parse_args()

    if args.url:
        input_source = args.url
    elif args.local:
        input_source = args.local
    else:
        parser.error('Either --url or --local must be provided.')

    converter = HtmlToMarkdownConverter(input_source, args.output, args.ignore_media)
    converter.process()