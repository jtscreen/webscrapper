import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from typing import List, Dict, Tuple, Optional

class UniversityEmailScraper:
    """
    A web scraper specifically designed to extract email addresses and associated names
    from university webpages using multiple pattern matching techniques.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # Email patterns for matching
        self.email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.edu\b',  # .edu emails
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'  # General email pattern
        ]

        # Name patterns - look for names near emails
        self.name_patterns = [
            r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # First Last
            r'\b[A-Z][a-z]+\s+[A-Z]\.\s*[A-Z][a-z]+\b',  # First M. Last
            r'\b[A-Z]\.\s*[A-Z][a-z]+\b',  # F. Last
            r'\b(Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Dr or Prof with optional period
            r'\b[A-Z][a-z]+,\s[A-Z][a-z]+\s[A-Z]\.\b',  # Last, First M.
            r'\b[A-Z][a-z]+,\s+[A-Z][a-z]\b'  # Last, First
        ]

    def decode_cloudflare_email(self, encoded_string: str) -> str:
        try:
            encoded_string = encoded_string.replace(' ', '')
            encoded_bytes = bytes.fromhex(encoded_string)
            key = encoded_bytes[0]
            decoded = ''.join(chr(byte ^ key) for byte in encoded_bytes[1:])
            return decoded
        except Exception as e:
            logging.error(f"Error decoding Cloudflare email: {e}")
            return ""

    def fetch_webpage(self, url: str) -> BeautifulSoup:
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {str(e)}")
            raise

    def extract_mailto_emails(self, soup: BeautifulSoup) -> List[Tuple[str, Optional[str]]]:
        results = []
        html_content = str(soup)
        mailto_pattern = r'mailto:([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})'
        html_mailto_matches = re.finditer(mailto_pattern, html_content, re.IGNORECASE)

        for match in html_mailto_matches:
            email = match.group(1).strip()
            if any(existing_email.lower() == email.lower() for existing_email, _ in results):
                continue
            start_pos = max(0, match.start() - 300)
            end_pos = min(len(html_content), match.end() + 300)
            context = html_content[start_pos:end_pos]
            try:
                context_soup = BeautifulSoup(context, 'html.parser')
                context_text = context_soup.get_text()
                name = self.extract_name_from_text(context_text)
            except:
                name = None
            results.append((email, name or "unknown"))
        return results

    def extract_text_emails(self, soup: BeautifulSoup) -> List[Tuple[str, Optional[str]]]:
        results = []
        text_content = soup.get_text()
        html_content = str(soup)
        all_patterns = [
            r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.edu(?:\.[A-Za-z]{2,})?',
            r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}',
            r'(?:email|e-?mail|contact)\s*[:\-=]\s*([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
            r'(?:data-email|email)["\'\s]*[=:]["\'\s]*([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        ]
        for content_type, content in [("text", text_content), ("html", html_content)]:
            for i, pattern in enumerate(all_patterns):
                email_matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in email_matches:
                    if match.groups():
                        email = match.group(1).strip()
                    else:
                        email = match.group().strip()
                    email = re.sub(r'[<>"\'&;]', '', email)
                    email = email.strip()
                    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
                        continue
                    if any(existing_email.lower() == email.lower() for existing_email, _ in results):
                        continue
                    start_pos = max(0, match.start() - 200)
                    end_pos = min(len(content), match.end() + 200)
                    context = content[start_pos:end_pos]
                    name = self.extract_name_from_text(context)
                    results.append((email, name or "unknown"))
        return results

    def extract_cloudflare_emails(self, soup: BeautifulSoup) -> List[Tuple[str, Optional[str]]]:
        results = []
        html_content = str(soup)
        cf_pattern = r'data-cfemail="([a-f0-9]+)"'
        cf_matches = re.finditer(cf_pattern, html_content, re.IGNORECASE)
        for match in cf_matches:
            encoded_email = match.group(1)
            if encoded_email:
                decoded_email = self.decode_cloudflare_email(encoded_email)
                if decoded_email and '@' in decoded_email:
                    start_pos = max(0, match.start() - 500)
                    end_pos = min(len(html_content), match.end() + 500)
                    context = html_content[start_pos:end_pos]
                    try:
                        context_soup = BeautifulSoup(context, 'html.parser')
                        context_text = context_soup.get_text()
                        name = self.extract_name_from_text(context_text)
                    except:
                        name = None
                    results.append((decoded_email, name or "unknown"))
        return results

    def extract_name_from_section(self, soup: BeautifulSoup, email: str) -> Optional[str]:
        try:
            email_elements = []
            for element in soup.find_all(text=True):
                if email.lower() in element.lower():
                    email_elements.append(element.parent if element.parent else element)
            for link in soup.find_all('a', href=True):
                if email.lower() in link['href'].lower():
                    email_elements.append(link)
            for element in soup.find_all():
                element_str = str(element)
                if email.lower() in element_str.lower():
                    email_elements.append(element)
            for email_element in email_elements:
                current_div = email_element
                while current_div and (not hasattr(current_div, 'name') or current_div.name != 'div'):
                    current_div = current_div.parent if hasattr(current_div, 'parent') else None
                for level in range(10):
                    if not current_div or not hasattr(current_div, 'name') or current_div.name != 'div':
                        break
                    heading_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']
                    for tag in heading_tags:
                        headings = current_div.find_all(tag) if hasattr(current_div, 'find_all') else []
                        for heading in headings:
                            heading_text = heading.get_text(strip=True)
                            if heading_text and len(heading_text) >= 2:
                                formatted_heading = self.format_comma_name(heading_text)
                                return formatted_heading
                    parent = current_div.parent if hasattr(current_div, 'parent') else None
                    while parent and (not hasattr(parent, 'name') or parent.name != 'div'):
                        parent = parent.parent if hasattr(parent, 'parent') else None
                    current_div = parent
            return None
        except Exception as e:
            logging.error(f"Error extracting name from section for {email}: {e}")
            return None

    def format_comma_name(self, name: str) -> str:
        if ',' in name:
            try:
                last, first = name.split(',', 1)
                formatted_name = f"{first.strip()} {last.strip()}"
            except Exception:
                formatted_name = name
        else:
            formatted_name = name
        if len(formatted_name) > 1:
            result = formatted_name[0]
            for i in range(1, len(formatted_name)):
                char = formatted_name[i]
                prev_char = formatted_name[i-1]
                if char.isupper() and prev_char != ' ':
                    result += ' ' + char
                else:
                    result += char
            formatted_name = result
        return formatted_name

    def generate_name_from_email(self, email: str) -> str:
        try:
            username = email.split('@')[0]
            if '.' in username:
                parts = username.split('.')
                name = ' '.join(part.capitalize() for part in parts if part)
                return name
            else:
                if len(username) > 0:
                    return f"{username[0].upper()}. {username[1:].capitalize()}"
                return username.capitalize()
        except Exception:
            return email.split('@')[0] if '@' in email else email

    def extract_name_from_text(self, text: str) -> Optional[str]:
        if not text:
            return None
        text = re.sub(r'\s+', ' ', text.strip())
        for pattern in self.name_patterns:
            matches = re.findall(pattern, text)
            if matches:
                name = matches[0].strip()
                name = re.sub(r'^(Dr\.|Prof\.)\s+', '', name)
                return name
        return None

    def check_name_in_email(self, name: str, email: str) -> bool:
        try:
            username = re.sub(r'\W', '', email.split('@')[0].lower())
            name_parts = [re.sub(r'\W', '', part.lower()) for part in name.split()]
            for part in name_parts:
                if not part:
                    continue
                if part in username or username.startswith(part) or username.endswith(part) or (len(part) == 1 and part == username[0]):
                    return True
            return False
        except Exception:
            return False

    def find_name_near_element(self, element) -> Optional[str]:
        parent = element.parent
        for _ in range(3):
            if parent:
                text = parent.get_text(strip=True)
                name = self.extract_name_from_text(text)
                if name:
                    return name
                parent = parent.parent
            else:
                break
        for sibling in element.find_next_siblings():
            text = sibling.get_text(strip=True) if hasattr(sibling, 'get_text') else str(sibling)
            name = self.extract_name_from_text(text)
            if name:
                return name
        for sibling in element.find_previous_siblings():
            text = sibling.get_text(strip=True) if hasattr(sibling, 'get_text') else str(sibling)
            name = self.extract_name_from_text(text)
            if name:
                return name
        return None

    def scrape_university_emails(self, url: str) -> List[Dict[str, str]]:
        try:
            soup = self.fetch_webpage(url)
            mailto_results = self.extract_mailto_emails(soup)
            text_results = self.extract_text_emails(soup)
            cloudflare_results = self.extract_cloudflare_emails(soup)
            all_results = mailto_results + text_results + cloudflare_results
            unique_results = []
            seen_emails = set()
            for email, name in all_results:
                email_lower = email.lower()
                if email_lower in seen_emails:
                    continue
                seen_emails.add(email_lower)
                section_name = self.extract_name_from_section(soup, email)
                if section_name:
                    final_name = section_name
                elif name and name != "unknown":
                    final_name = self.format_comma_name(name)
                else:
                    final_name = self.generate_name_from_email(email)
                unique_results.append({
                    'email': email,
                    'name': final_name
                })
            return unique_results
        except Exception as e:
            logging.error(f"Error scraping {url}: {str(e)}")
            raise

# === Sample usage ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    url = "https://www.exampleuniversity.edu/faculty"
    scraper = UniversityEmailScraper()
    try:
        results = scraper.scrape_university_emails(url)
        for entry in results:
            print(entry)
    except Exception as e:
        print(f"Failed to scrape: {e}")
