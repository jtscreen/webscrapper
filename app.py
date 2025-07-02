import os
import logging
from flask import Flask, request, jsonify, send_from_directory
from scraper import UniversityEmailScraper
from urllib.parse import urlparse

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Initialize the email scraper
email_scraper = UniversityEmailScraper()

@app.route('/')
def serve_index():
    """Serve the main HTML file"""
    return send_from_directory('.', 'index.html')

@app.route('/api/scrape', methods=['POST'])
def scrape_emails():
    """API endpoint to handle scraping requests"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'success': False, 'error': 'Please enter a URL'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL format
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return jsonify({'success': False, 'error': 'Please enter a valid URL'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': f'Invalid URL format: {str(e)}'}), 400
        
        app.logger.info(f"Starting to scrape URL: {url}")
        
        # Perform the scraping
        results = email_scraper.scrape_university_emails(url)
        
        app.logger.info(f"Found {len(results)} email-name pairs")
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results),
            'url': url
        })
            
    except Exception as e:
        app.logger.error(f"Error during scraping: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Error occurred while scraping: {str(e)}'}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    app.logger.error(f"Internal server error: {str(e)}", exc_info=True)
    return jsonify({'success': False, 'error': 'An internal error occurred. Please try again.'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)