import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import time
from typing import Set, List, Dict, Optional
import logging

class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, delay: float = 1.0):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.delay = delay
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.forms: List[Dict] = []
        self.parameters: Dict[str, Set[str]] = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecurityAuditTool/1.0'
        })
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def is_valid_url(self, url: str) -> bool:
        """Check if URL belongs to target domain"""
        parsed = urlparse(url)
        return parsed.netloc == self.domain

    def extract_links(self, soup: BeautifulSoup, current_url: str) -> Set[str]:
        """Extract all links from HTML content"""
        links = set()
        
        # Extract from anchor tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(current_url, href)
            if self.is_valid_url(full_url):
                # Remove fragments and normalize
                clean_url = full_url.split('#')[0]
                links.add(clean_url)
        
        # Extract from form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = urljoin(current_url, action)
            if self.is_valid_url(full_url):
                links.add(full_url)
        
        return links

    def extract_forms(self, soup: BeautifulSoup, current_url: str) -> List[Dict]:
        """Extract form information for vulnerability testing"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'url': current_url,
                'action': urljoin(current_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms

    def extract_parameters(self, url: str) -> Set[str]:
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return set(params.keys())

    def crawl_page(self, url: str) -> Optional[BeautifulSoup]:
        """Crawl a single page and extract information"""
        try:
            self.logger.info(f"Crawling: {url}")
            response = self.session.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Only process HTML content
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return None
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract parameters from URL
            params = self.extract_parameters(url)
            if params:
                if url not in self.parameters:
                    self.parameters[url] = set()
                self.parameters[url].update(params)
            
            # Extract forms
            page_forms = self.extract_forms(soup, url)
            self.forms.extend(page_forms)
            
            return soup
            
        except requests.RequestException as e:
            self.logger.error(f"Error crawling {url}: {e}")
            return None

    def crawl(self, start_url: Optional[str] = None, authenticated: bool = False, 
              auth_cookies: Optional[Dict] = None) -> Dict:
        """Main crawling function"""
        if start_url is None:
            start_url = self.base_url
        
        # Set authentication cookies if provided
        if authenticated and auth_cookies:
            self.session.cookies.update(auth_cookies)
        
        urls_to_visit = [(start_url, 0)]  # (url, depth)
        
        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)
            
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            self.visited_urls.add(current_url)
            self.discovered_endpoints.add(current_url)
            
            soup = self.crawl_page(current_url)
            if soup is None:
                continue
            
            # Extract new links if within depth limit
            if depth < self.max_depth:
                new_links = self.extract_links(soup, current_url)
                for link in new_links:
                    if link not in self.visited_urls:
                        urls_to_visit.append((link, depth + 1))
            
            # Respect rate limiting
            time.sleep(self.delay)
        
        return self.get_results()

    def get_results(self) -> Dict:
        """Return crawling results"""
        return {
            'endpoints': list(self.discovered_endpoints),
            'forms': self.forms,
            'parameters': {url: list(params) for url, params in self.parameters.items()},
            'total_pages': len(self.visited_urls)
        }

    def discover_api_endpoints(self) -> List[str]:
        """Discover potential API endpoints"""
        api_patterns = [
            '/api/', '/v1/', '/v2/', '/rest/', '/graphql',
            '.json', '.xml', '/admin/', '/dashboard/'
        ]
        
        api_endpoints = []
        for endpoint in self.discovered_endpoints:
            for pattern in api_patterns:
                if pattern in endpoint.lower():
                    api_endpoints.append(endpoint)
                    break
        
        return api_endpoints

if __name__ == "__main__":
    # Example usage
    crawler = WebCrawler("http://example.com", max_depth=2)
    results = crawler.crawl()
    print(f"Discovered {len(results['endpoints'])} endpoints")
    print(f"Found {len(results['forms'])} forms")
