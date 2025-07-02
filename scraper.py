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
            r'\bDr\.\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Dr. First Last
            r'\bProf\.\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',  # Prof. First Last
        ]

    def decode_cloudflare_email(self, encoded_string: str) -> str:
        """
        Decode Cloudflare-protected email addresses.
        
        Args:
            encoded_string: The encoded email string from data-cfemail attribute
            
        Returns:
            Decoded email address
        """
        try:
            # Remove any spaces and convert to bytes
            encoded_string = encoded_string.replace(' ', '')
            
            # Convert hex string to bytes
            encoded_bytes = bytes.fromhex(encoded_string)
            
            # First byte is the key
            key = encoded_bytes[0]
            
            # Decode the rest using XOR
            decoded = ''.join(chr(byte ^ key) for byte in encoded_bytes[1:])
            
            return decoded
        except Exception as e:
            logging.error(f"Error decoding Cloudflare email: {e}")
            return ""
    
    def fetch_webpage(self, url: str) -> BeautifulSoup:
        """
        Fetch and parse a webpage, returning a BeautifulSoup object.
        
        Args:
            url: The URL to fetch
            
        Returns:
            BeautifulSoup object of the parsed HTML
            
        Raises:
            requests.RequestException: If the request fails
        """
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse the HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup
            
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {str(e)}")
            raise
    
    def extract_mailto_emails(self, soup: BeautifulSoup) -> List[Tuple[str, Optional[str]]]:
        """
        Extract emails from mailto: links and attempt to find associated names.
        
        Args:
            soup: BeautifulSoup object of the webpage
            
        Returns:
            List of (email, name) tuples
        """
        results = []
        
        # Search for mailto in the raw HTML - this is the most reliable approach
        html_content = str(soup)
        # More comprehensive mailto pattern
        mailto_pattern = r'mailto:([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})'
        html_mailto_matches = re.finditer(mailto_pattern, html_content, re.IGNORECASE)
        
        # Process mailto links found in HTML source
        for match in html_mailto_matches:
            email = match.group(1).strip()
            
            # Skip if we already found this email
            if any(existing_email.lower() == email.lower() for existing_email, _ in results):
                continue
            
            # Look for name in surrounding HTML context
            start_pos = max(0, match.start() - 300)
            end_pos = min(len(html_content), match.end() + 300)
            context = html_content[start_pos:end_pos]
            
            # Remove HTML tags from context for name extraction
            try:
                context_soup = BeautifulSoup(context, 'html.parser')
                context_text = context_soup.get_text()
                name = self.extract_name_from_text(context_text)
            except:
                name = None
            
            results.append((email, name or "unknown"))
            logging.debug(f"Found mailto email: {email} with name: {name or 'unknown'}")
                
        return results
    
    def extract_text_emails(self, soup: BeautifulSoup) -> List[Tuple[str, Optional[str]]]:
        """
        Extract emails from text content, looking for "email:" patterns and .edu addresses.
        
        Args:
            soup: BeautifulSoup object of the webpage
            
        Returns:
            List of (email, name) tuples
        """
        results = []
        
        # Get both visible text and HTML source for broader search
        text_content = soup.get_text()
        html_content = str(soup)
        
        # Enhanced email patterns - more comprehensive and flexible
        all_patterns = [
            # Most comprehensive .edu email pattern
            r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.edu(?:\.[A-Za-z]{2,})?',
            # General email pattern - very broad
            r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}',
            # Email with various labels (capture group)
            r'(?:email|e-?mail|contact)\s*[:\-=]\s*([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
            # Email in attributes or hidden fields
            r'(?:data-email|email)["\'\s]*[=:]["\'\s]*([A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        ]
        
        # Search in both text and HTML content
        for content_type, content in [("text", text_content), ("html", html_content)]:
            for i, pattern in enumerate(all_patterns):
                email_matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in email_matches:
                    # Extract email - some patterns have groups, others don't
                    if match.groups():
                        email = match.group(1).strip()
                    else:
                        email = match.group().strip()
                    
                    # Clean up email (remove any HTML artifacts and unwanted characters)
                    email = re.sub(r'[<>"\'&;]', '', email)
                    email = email.strip()
                    
                    # Validate email format
                    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
                        continue
                    
                    # Skip if we already found this email
                    if any(existing_email.lower() == email.lower() for existing_email, _ in results):
                        continue
                    
                    # Look for name in surrounding context
                    start_pos = max(0, match.start() - 200)
                    end_pos = min(len(content), match.end() + 200)
                    context = content[start_pos:end_pos]
                    
                    name = self.extract_name_from_text(context)
                    results.append((email, name or "unknown"))
                    
                    logging.info(f"Found email: {email} with name: {name or 'unknown'} (pattern {i+1}, {content_type})")
        
        # If no results found with standard patterns, try extracting any .edu strings
        if not results:
            logging.info("No emails found with standard patterns, trying .edu extraction")
            
            # Very broad .edu extraction - get any text that looks like it could be an email
            edu_extraction_patterns = [
                # Standard email with .edu
                r'[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.edu(?:\.[A-Za-z]{2,})?',
                # Obfuscated patterns
                r'[A-Za-z0-9][A-Za-z0-9._%+-]*\s*\[?at\]?\s*[A-Za-z0-9.-]*\.edu',
                r'[A-Za-z0-9][A-Za-z0-9._%+-]*\s*&#64;\s*[A-Za-z0-9.-]*\.edu',
                # Spaced out patterns
                r'[A-Za-z0-9][A-Za-z0-9._%+-]*\s*@\s*[A-Za-z0-9.-]*\s*\.\s*edu',
            ]
            
            for content_type, content in [("text", text_content), ("html", html_content)]:
                for pattern in edu_extraction_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        email_like = match.group().strip()
                        
                        # Clean up and normalize
                        email_like = re.sub(r'\s+', ' ', email_like)  # normalize spaces
                        email_like = re.sub(r'\[?at\]?', '@', email_like)  # replace 'at' with @
                        email_like = re.sub(r'&#64;', '@', email_like)  # replace HTML entity
                        email_like = re.sub(r'\s+', '', email_like)  # remove all spaces
                        
                        # Skip if already found
                        if any(existing_email.lower() == email_like.lower() for existing_email, _ in results):
                            continue
                        
                        # Basic validation - must have @ and .edu
                        if '@' in email_like and '.edu' in email_like.lower():
                            # Look for name in surrounding context
                            start_pos = max(0, match.start() - 200)
                            end_pos = min(len(content), match.end() + 200)
                            context = content[start_pos:end_pos]
                            
                            name = self.extract_name_from_text(context)
                            results.append((email_like, name or "unknown"))
                            
                            logging.info(f"Extracted .edu string: {email_like} with name: {name or 'unknown'}")
        
        return results
    
    def extract_cloudflare_emails(self, soup: BeautifulSoup) -> List[Tuple[str, Optional[str]]]:
        """
        Extract Cloudflare-protected emails from data-cfemail attributes.
        
        Args:
            soup: BeautifulSoup object of the webpage
            
        Returns:
            List of (email, name) tuples
        """
        results = []
        
        # Search for data-cfemail in the HTML source directly
        html_content = str(soup)
        cf_pattern = r'data-cfemail="([a-f0-9]+)"'
        cf_matches = re.finditer(cf_pattern, html_content, re.IGNORECASE)
        
        for match in cf_matches:
            encoded_email = match.group(1)
            if encoded_email:
                decoded_email = self.decode_cloudflare_email(encoded_email)
                
                if decoded_email and '@' in decoded_email:
                    # Look for name in surrounding HTML context
                    start_pos = max(0, match.start() - 500)
                    end_pos = min(len(html_content), match.end() + 500)
                    context = html_content[start_pos:end_pos]
                    
                    # Remove HTML tags from context for name extraction
                    try:
                        context_soup = BeautifulSoup(context, 'html.parser')
                        context_text = context_soup.get_text()
                        name = self.extract_name_from_text(context_text)
                    except:
                        name = None
                    
                    results.append((decoded_email, name or "unknown"))
                    
                    logging.info(f"Decoded Cloudflare email: {decoded_email} with name: {name or 'unknown'}")
        
        return results
    
    def extract_name_from_text(self, text: str) -> Optional[str]:
        """
        Extract a person's name from a text string using pattern matching.
        
        Args:
            text: Text to search for names
            
        Returns:
            Extracted name or None if not found
        """
        if not text:
            return None
            
        # Clean the text
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Try each name pattern
        for pattern in self.name_patterns:
            matches = re.findall(pattern, text)
            if matches:
                # Return the first match, cleaned up
                name = matches[0].strip()
                # Remove common prefixes if they exist standalone
                name = re.sub(r'^(Dr\.|Prof\.)\s+', '', name)
                return name
                
        return None
    

    
    def find_name_near_element(self, element) -> Optional[str]:
        """
        Look for a name in the vicinity of a given HTML element.
        
        Args:
            element: BeautifulSoup element to search around
            
        Returns:
            Found name or None
        """
        # Check parent elements
        parent = element.parent
        for _ in range(3):  # Check up to 3 levels up
            if parent:
                text = parent.get_text(strip=True)
                name = self.extract_name_from_text(text)
                if name:
                    return name
                parent = parent.parent
            else:
                break
        
        # Check sibling elements
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
        """
        Main method to scrape emails and names from a university webpage.
        
        Args:
            url: URL of the university webpage to scrape
            
        Returns:
            List of dictionaries with 'email' and 'name' keys
        """
        try:
            # Fetch the webpage
            soup = self.fetch_webpage(url)
            
            # Add debug logging to see what content we're working with
            page_text = soup.get_text()
            html_content = str(soup)
            
            # Log some basic info about the page
            logging.info(f"Page text length: {len(page_text)}")
            logging.info(f"HTML content length: {len(html_content)}")
            
            # Check for any .edu addresses in the content
            edu_count = len(re.findall(r'\.edu\b', page_text + html_content, re.IGNORECASE))
            logging.info(f"Found {edu_count} instances of '.edu' in the page")
            
            # Try a very broad email search for debugging
            broad_email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
            broad_emails = re.findall(broad_email_pattern, page_text + html_content, re.IGNORECASE)
            logging.info(f"Broad email search found: {len(broad_emails)} potential emails")
            if broad_emails:
                logging.info(f"Sample emails found: {broad_emails[:5]}")
            
            # Extract any strings containing .edu with surrounding context
            edu_pattern = r'[A-Za-z0-9._%+-]*[A-Za-z0-9._%+-]+@[^@\s]*\.edu[A-Za-z0-9.]*'
            edu_strings = re.findall(edu_pattern, page_text + html_content, re.IGNORECASE)
            logging.info(f"Strings containing .edu: {len(edu_strings)} found")
            if edu_strings:
                unique_edu_strings = list(set(edu_strings))
                logging.info(f"Unique .edu strings: {unique_edu_strings[:10]}")
            
            # Also look for obfuscated emails (common patterns)
            obfuscated_patterns = [
                r'[A-Za-z0-9._%+-]+\s*\[?at\]?\s*[A-Za-z0-9.-]*\.edu',
                r'[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]*\s*\.\s*edu',
                r'[A-Za-z0-9._%+-]+\s*&#64;\s*[A-Za-z0-9.-]*\.edu',
            ]
            
            for pattern in obfuscated_patterns:
                obfuscated = re.findall(pattern, page_text + html_content, re.IGNORECASE)
                if obfuscated:
                    logging.info(f"Obfuscated emails found: {obfuscated[:5]}")
            
            # Check for mailto occurrences
            mailto_count = len(re.findall(r'mailto:', html_content, re.IGNORECASE))
            logging.info(f"Found {mailto_count} instances of 'mailto:' in the page")
            
            # Check for email: patterns
            email_label_count = len(re.findall(r'email\s*:', page_text, re.IGNORECASE))
            logging.info(f"Found {email_label_count} instances of 'email:' pattern in the page")
            
            # Extract emails using different methods
            mailto_results = self.extract_mailto_emails(soup)
            text_results = self.extract_text_emails(soup)
            cloudflare_results = self.extract_cloudflare_emails(soup)
            
            logging.info(f"Mailto results: {len(mailto_results)}")
            logging.info(f"Text results: {len(text_results)}")
            logging.info(f"Cloudflare results: {len(cloudflare_results)}")
            
            # Combine results and remove duplicates
            all_results = mailto_results + text_results + cloudflare_results
            unique_results = []
            seen_emails = set()
            
            for email, name in all_results:
                email_lower = email.lower()
                if email_lower not in seen_emails:
                    seen_emails.add(email_lower)
                    unique_results.append({
                        'email': email,
                        'name': name if name and name != "unknown" else "unknown"
                    })
            
            logging.info(f"Successfully extracted {len(unique_results)} unique email-name pairs from {url}")
            return unique_results
            
        except Exception as e:
            logging.error(f"Error scraping {url}: {str(e)}")
            raise
