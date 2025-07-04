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
            r'\b[A-Z][a-z]+,\s[A-Z][a-z]+\s[A-Z]\.\b',  #Last, First M.
            r'\b[A-Z][a-z]+,\s+[A-Z][a-z]\b'  #Last, First
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
    
    def extract_name_from_section(self, soup: BeautifulSoup, email: str) -> Optional[str]:
        """
        Extract name from a section by finding the email first, then searching for h tags
        in div containers, comparing last two characters.
        
        Args:
            soup: BeautifulSoup object of the webpage
            email: Email address to search for in sections
            
        Returns:
            Extracted name from h tag or None if not found
        """
        try:
            # Extract username from email (part before @)
            username = email.split('@')[0] if '@' in email else email
            username_last2 = username[-2:].lower() if len(username) >= 2 else username.lower()
            username_first2 = username[:2].lower() if len(username) >= 2 else username.lower()
            
            logging.debug(f"Searching for h tags for email: {email}, username: {username}, last2: {username_last2}, first2: {username_first2}")
            
            # First, find all elements that contain the email address
            email_elements = []
            
            # Search in text content
            for element in soup.find_all(text=True):
                if email.lower() in element.lower():
                    email_elements.append(element.parent if element.parent else element)
            
            # Search in href attributes (mailto links)
            for link in soup.find_all('a', href=True):
                if email.lower() in link['href'].lower():
                    email_elements.append(link)
            
            # Search in other attributes that might contain emails
            for element in soup.find_all():
                element_str = str(element)
                if email.lower() in element_str.lower():
                    email_elements.append(element)
            
            logging.debug(f"Found {len(email_elements)} elements containing email {email}")
            
            # For each element containing the email, traverse up parent divs
            for email_element in email_elements:
                current_div = email_element
                
                # Find the nearest parent div
                while current_div and (not hasattr(current_div, 'name') or current_div.name != 'div'):
                    current_div = current_div.parent if hasattr(current_div, 'parent') else None
                
                # Now start the loop through div containers
                for level in range(10):  # Maximum 10 levels up
                    if not current_div or not hasattr(current_div, 'name') or current_div.name != 'div':
                        break
                    
                    logging.debug(f"Level {level}: Searching in div container")
                    
                    # Search for h tags (h1-h6) in current div container
                    heading_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']
                    h_tag_found = False
                    
                    for tag in heading_tags:
                        headings = current_div.find_all(tag) if hasattr(current_div, 'find_all') else []
                        for heading in headings:
                            h_tag_found = True
                            heading_text = heading.get_text(strip=True)
                            
                            if heading_text and len(heading_text) >= 2:
                                heading_last2 = heading_text[-2:].lower()
                                
                                logging.debug(f"Found {tag}: '{heading_text}', last2: '{heading_last2}' vs username last2: '{username_last2}'")
                                
                                # Format comma name right after finding h tag
                                formatted_heading = self.format_comma_name(heading_text)
                                logging.debug(f"📝 Formatted heading: '{heading_text}' -> '{formatted_heading}'")
                                
                                # Now use formatted name for comparison
                                if len(formatted_heading) >= 2:
                                    formatted_heading_last2 = formatted_heading[-2:].lower()
                                    formatted_heading_first2 = formatted_heading[:2].lower()
                                    
                                    logging.debug(f"🔤 Formatted heading last 2 chars: '{formatted_heading_last2}' vs username last2: '{username_last2}'")
                                    logging.debug(f"🔤 Formatted heading first 2 chars: '{formatted_heading_first2}' vs username first2: '{username_first2}'")
                                    
                                    # Compare last 2 characters
                                    if formatted_heading_last2 == username_last2:
                                        logging.debug(f"✅ H tag last 2 chars match! Using: {formatted_heading}")
                                        return formatted_heading
                                    
                                    # Check first 2 characters
                                    if formatted_heading_first2 == username_first2:
                                        logging.debug(f"✅ H tag first 2 chars match! Using: {formatted_heading}")
                                        return formatted_heading
                                
                                # Both last 2 and first 2 don't match
                                logging.debug(f"❌ Both first and last 2 chars don't match for: {formatted_heading}")
                    
                    # If we found h tags but none matched, go to parent div
                    if h_tag_found:
                        logging.debug(f"Found h tags at level {level} but none matched, going to parent div")
                    else:
                        logging.debug(f"No h tags found at level {level}, going to parent div")
                    
                    # Move to parent div container
                    parent = current_div.parent if hasattr(current_div, 'parent') else None
                    while parent and (not hasattr(parent, 'name') or parent.name != 'div'):
                        parent = parent.parent if hasattr(parent, 'parent') else None
                    
                    current_div = parent
            
            logging.debug(f"No matching h tags found for email {email}")
            return None
            
        except Exception as e:
            logging.error(f"Error extracting name from section for {email}: {e}")
            return None

    def format_comma_name(self, name: str) -> str:
        """
        Format a name that contains a comma by splitting on comma 
        and reformatting as "first last". Also adds spaces before 
        capital letters (excluding the first character).
        
        Args:
            name: Name string that may contain a comma
            
        Returns:
            Formatted name string
        """
        # First handle comma formatting
        if ',' in name:
            try:
                last, first = name.split(',', 1)  # Split only on first comma
                formatted_name = f"{first.strip()} {last.strip()}"
            except Exception:
                # Fallback to original name if anything goes wrong
                formatted_name = name
        else:
            formatted_name = name
        
        # Now check for capital letters (excluding the first) and add spaces before them
        if len(formatted_name) > 1:
            result = formatted_name[0]  # Start with first character
            
            for i in range(1, len(formatted_name)):
                char = formatted_name[i]
                prev_char = formatted_name[i-1]
                
                # If current character is uppercase and previous character is not a space
                if char.isupper() and prev_char != ' ':
                    result += ' ' + char
                else:
                    result += char
            
            formatted_name = result
        
        print(formatted_name)
        return formatted_name

    def generate_name_from_email(self, email: str) -> str:
        """
        Generate a name from email address using specific logic:
        1. Extract username part (before @)
        2. If email contains "." before @, format as "First Last" 
        3. If no ".", format as "F. Username"
        
        Args:
            email: Email address to process
            
        Returns:
            Generated name string
        """
        try:
            # Extract username part before @
            username = email.split('@')[0]
            
            # Check if username contains a dot
            if '.' in username:
                # Split on dot and capitalize each part
                parts = username.split('.')
                # Join with space, capitalizing first letter of each part
                name = ' '.join(part.capitalize() for part in parts if part)
                return name
            else:
                # No dot - format as "F. Username"
                if len(username) > 0:
                    return f"{username[0].upper()}. {username[1:].capitalize()}"
                return username.capitalize()
                
        except Exception:
            # Fallback to original username if anything goes wrong
            return email.split('@')[0] if '@' in email else email

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
                    
                    # Apply the new name extraction and validation logic
                    final_name = name
                    
                    # First, try to extract name from section (div with image and email)
                    section_name = self.extract_name_from_section(soup, email)
                    logging.info(f"🔍 Processing email: {email}")
                    logging.info(f"📧 Original extracted name: {name}")
                    logging.info(f"🏷️ Section-based name: {section_name}")
                    
                    if section_name:
                        # Found a name from section, validate it
                        username = email.split('@')[0] if '@' in email else email
                        logging.info(f"👤 Username from email: {username}")
                        
                        # Section name is already formatted in extract_name_from_section
                        
                        if len(section_name) >= 2 and len(username) >= 2:
                            section_last2 = section_name[-2:].lower()
                            username_last2 = username[-2:].lower()
                            section_first2 = section_name[:2].lower()
                            username_first2 = username[:2].lower()
                            
                            logging.info(f"🔤 Section name last 2 chars: '{section_last2}' vs Username last 2 chars: '{username_last2}'")
                            logging.info(f"🔤 Section name first 2 chars: '{section_first2}' vs Username first 2 chars: '{username_first2}'")
                            
                            # Check if either first 2 or last 2 characters match
                            if section_last2 == username_last2 or section_first2 == username_first2:
                                # At least one pair matches, use the section name
                                final_name = section_name
                                logging.info(f"✅ At least one character pair matches! Using section name: {final_name}")
                            else:
                                # Both first 2 and last 2 don't match, use email-based name generation
                                final_name = self.generate_name_from_email(email)
                                logging.info(f"❌ Both character pairs don't match! Generated name from email: {final_name}")
                        else:
                            # Use section name if we can't compare (too short)
                            final_name = section_name
                            logging.info(f"⚠️ Can't compare (too short). Using section name: {final_name}")
                    
                    elif not name or name == "unknown":
                        # No section name and no original name found, generate from email
                        final_name = self.generate_name_from_email(email)
                        logging.info(f"🔧 No section/original name found. Generated from email: {final_name}")
                    
                    else:
                        # Have an original name but no section name, validate original name
                        username = email.split('@')[0] if '@' in email else email
                        logging.info(f"👤 Username from email: {username}")
                        
                        # Apply comma formatting to original name after finding it
                        formatted_original_name = self.format_comma_name(name)
                        
                        if len(formatted_original_name) >= 2 and len(username) >= 2:
                            name_last2 = formatted_original_name[-2:].lower()
                            username_last2 = username[-2:].lower()
                            name_first2 = formatted_original_name[:2].lower()
                            username_first2 = username[:2].lower()
                            
                            logging.info(f"🔤 Original name last 2 chars: '{name_last2}' vs Username last 2 chars: '{username_last2}'")
                            logging.info(f"🔤 Original name first 2 chars: '{name_first2}' vs Username first 2 chars: '{username_first2}'")
                            
                            # Check if either first 2 or last 2 characters match
                            if name_last2 == username_last2 or name_first2 == username_first2:
                                # At least one pair matches, use the original name
                                final_name = formatted_original_name
                                logging.info(f"✅ At least one character pair matches! Using original name: {final_name}")
                            else:
                                # Both first 2 and last 2 don't match, use email-based name generation
                                final_name = self.generate_name_from_email(email)
                                logging.info(f"❌ Both character pairs don't match! Generated name from email: {final_name}")
                        else:
                            final_name = formatted_original_name
                            logging.info(f"⚠️ Can't compare (too short). Using original name: {final_name}")
                    
                    logging.info(f"🎯 Final name decision for {email}: {final_name}")
                    logging.info("=" * 60)
                    
                    unique_results.append({
                        'email': email,
                        'name': final_name
                    })
            
            logging.info(f"Successfully extracted {len(unique_results)} unique email-name pairs from {url}")
            return unique_results
            
        except Exception as e:
            logging.error(f"Error scraping {url}: {str(e)}")
            raise
