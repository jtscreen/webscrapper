import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
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
        """
        Decode Cloudflare-protected email addresses.
        """
        try:
            encoded_string = encoded_string.replace(' ', '')
            encoded_bytes = bytes.fromhex(encoded_string)
            key = encoded_bytes[0]
            decoded = ''.join(chr(byte ^ key) for byte in encoded_bytes[1:])
            return decoded
        except Exception:
            return ""

    def fetch_webpage(self, url: str) -> BeautifulSoup:
        """
        Fetch and parse a webpage, returning a BeautifulSoup object.
        """
        response = self.session.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup

    def is_valid_email(self, email: str) -> bool:
        """
        Validate email format.
        """
        return re.match(r'^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email) is not None

    def get_context(self, content: str, match, window: int = 200) -> str:
        """
        Extract context around a regex match.
        """
        start = max(0, match.start() - window)
        end = min(len(content), match.end() + window)
        return content[start:end]

    def extract_emails_with_patterns(self, content: str, patterns: List[str]) -> List[Tuple[str, str]]:
        """
        Extract emails from content using provided patterns.
        """
        results = []
        found = set()
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                email = match.group(1) if match.groups() else match.group()
                email = re.sub(r'[<>"\'&;]', '', email).strip()
                if not self.is_valid_email(email) or email.lower() in found:
                    continue
                context = self.get_context(content, match)
                name = self.extract_name_from_text(context) or "unknown"
                results.append((email, name))
                found.add(email.lower())
        return results

    def extract_cloudflare_emails(self, soup: BeautifulSoup) -> List[Tuple[str, str]]:
        """
        Extract Cloudflare-protected emails from data-cfemail attributes.
        """
        results = []
        html_content = str(soup)
        cf_pattern = r'data-cfemail="([a-f0-9]+)"'
        for match in re.finditer(cf_pattern, html_content, re.IGNORECASE):
            encoded_email = match.group(1)
            if encoded_email:
                decoded_email = self.decode_cloudflare_email(encoded_email)
                if decoded_email and '@' in decoded_email:
                    context = self.get_context(html_content, match, 500)
                    try:
                        context_soup = BeautifulSoup(context, 'html.parser')
                        context_text = context_soup.get_text()
                        name = self.extract_name_from_text(context_text)
                    except Exception:
                        name = None
                    results.append((decoded_email, name or "unknown"))
        return results

    def extract_name_from_section(self, soup: BeautifulSoup, email: str) -> Optional[str]:
        """
        Extract name from a section by finding the email first, then searching for h tags
        in div containers, comparing last two characters.
        """
        try:
            username = email.split('@')[0] if '@' in email else email
            username_last2 = username[-2:].lower() if len(username) >= 2 else username.lower()
            username_first2 = username[:2].lower() if len(username) >= 2 else username.lower()
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
                for _ in range(10):
                    if not current_div or not hasattr(current_div, 'name') or current_div.name != 'div':
                        break
                    heading_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']
                    for tag in heading_tags:
                        headings = current_div.find_all(tag) if hasattr(current_div, 'find_all') else []
                        for heading in headings:
                            heading_text = heading.get_text(strip=True)
                            formatted_heading = self.format_comma_name(heading_text)
                            if len(formatted_heading) >= 2:
                                formatted_heading_last2 = formatted_heading[-2:].lower()
                                formatted_heading_first2 = formatted_heading[:2].lower()
                                if formatted_heading_last2 == username_last2:
                                    return formatted_heading
                                if formatted_heading_first2 == username_first2:
                                    return formatted_heading
                    parent = current_div.parent if hasattr(current_div, 'parent') else None
                    while parent and (not hasattr(parent, 'name') or parent.name != 'div'):
                        parent = parent.parent if hasattr(parent, 'parent') else None
                    current_div = parent
            return None
        except Exception:
            return None

    def format_comma_name(self, name: str) -> str:
        """
        Format a name that contains a comma by splitting on comma 
        and reformatting as "first last". Also adds spaces before 
        capital letters (excluding the first character).
        """
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
        """
        Generate a name from email address using specific logic:
        1. Extract username part (before @)
        2. If email contains "." before @, format as "First Last" 
        3. If no ".", format as "F. Username"
        """
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
        """
        Extract a person's name from a text string using pattern matching.
        """
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

    def scrape_university_emails(self, url: str) -> List[Dict[str, str]]:
        """
        Main method to scrape emails and names from a university webpage.
        """
        try:
            soup = self.fetch_webpage(url)
            html_content = str(soup)
            text_content = soup.get_text()
            # Email extraction patterns
            all_patterns = [
                r'mailto:([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
                r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.edu(?:\.[A-Za-z]{2,})?',
                r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}',
                r'(?:email|e-?mail|contact)\s*[:\-=]\s*([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
                r'(?:data-email|email)["\'\s]*[=:]["\'\s]*([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
            ]
            all_results = []
            # Extract emails from text and html
            for content in [text_content, html_content]:
                all_results += self.extract_emails_with_patterns(content, all_patterns)
            # Extract Cloudflare-protected emails
            all_results += self.extract_cloudflare_emails(soup)
            # Remove duplicates and finalize names
            unique_results = []
            seen_emails = set()
            for email, name in all_results:
                email_lower = email.lower()
                if email_lower in seen_emails:
                    continue
                seen_emails.add(email_lower)
                final_name = name
                # Try to extract name from section
                section_name = self.extract_name_from_section(soup, email)
                if section_name:
                    username = email.split('@')[0] if '@' in email else email
                    if len(section_name) >= 2 and len(username) >= 2:
                        section_last2 = section_name[-2:].lower()
                        username_last2 = username[-2:].lower()
                        section_first2 = section_name[:2].lower()
                        username_first2 = username[:2].lower()
                        if section_last2 == username_last2 or section_first2 == username_first2:
                            final_name = section_name
                        else:
                            final_name = self.generate_name_from_email(email)
                    else:
                        final_name = section_name
                elif not name or name == "unknown":
                    final_name = self.generate_name_from_email(email)
                else:
                    username = email.split('@')[0] if '@' in email else email
                    formatted_original_name = self.format_comma_name(name)
                    if len(formatted_original_name) >= 2 and len(username) >= 2:
                        name_last2 = formatted_original_name[-2:].lower()
                        username_last2 = username[-2:].lower()
                        name_first2 = formatted_original_name[:2].lower()
                        username_first2 = username[:2].lower()
                        if name_last2 == username_last2 or name_first2 == username_first2:
                            final_name = formatted_original_name
                        else:
                            final_name = self.generate_name_from_email(email)
                    else:
                        final_name = formatted_original_name
                unique_results.append({
                    'email': email,
                    'name': final_name
                })
            return unique_results
        except Exception:
            raise
