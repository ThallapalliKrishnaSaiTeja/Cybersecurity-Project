import requests
from typing import Dict, Optional, List, Tuple
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
import json
import os

class AuthenticationManager:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecurityAuditTool/1.0'
        })
        self.authenticated = False
        self.auth_cookies = {}
        self.auth_headers = {}
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def find_login_forms(self, base_url: str) -> List[Dict]:
        """Discover login forms on the target website"""
        login_forms = []
        
        # Common login page paths
        login_paths = [
            '/login', '/signin', '/auth', '/admin', '/admin/login',
            '/user/login', '/account/login', '/wp-admin', '/wp-login.php'
        ]
        
        for path in login_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    forms = self.extract_login_forms(soup, url)
                    login_forms.extend(forms)
                    
            except requests.RequestException as e:
                self.logger.debug(f"Error checking login path {path}: {e}")
        
        # Also check the main page for login forms
        try:
            response = self.session.get(base_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                forms = self.extract_login_forms(soup, base_url)
                login_forms.extend(forms)
        except requests.RequestException as e:
            self.logger.error(f"Error checking main page for login forms: {e}")
        
        return login_forms

    def extract_login_forms(self, soup: BeautifulSoup, page_url: str) -> List[Dict]:
        """Extract potential login forms from HTML"""
        login_forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'url': page_url,
                'action': urljoin(page_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'is_login_form': False
            }
            
            # Extract input fields
            username_field = None
            password_field = None
            
            for input_tag in form.find_all(['input', 'textarea']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', ''),
                    'id': input_tag.get('id', '')
                }
                
                if input_data['name']:
                    form_data['inputs'].append(input_data)
                    
                    # Identify username/email fields
                    if (input_data['type'] in ['text', 'email'] and 
                        any(keyword in input_data['name'].lower() for keyword in 
                            ['user', 'email', 'login', 'account'])):
                        username_field = input_data['name']
                    
                    # Identify password fields
                    if input_data['type'] == 'password':
                        password_field = input_data['name']
            
            # Determine if this is likely a login form
            if username_field and password_field:
                form_data['is_login_form'] = True
                form_data['username_field'] = username_field
                form_data['password_field'] = password_field
                login_forms.append(form_data)
        
        return login_forms

    def authenticate_form_based(self, login_form: Dict, username: str, 
                              password: str) -> bool:
        """Attempt form-based authentication"""
        try:
            # Prepare form data
            form_data = {}
            
            # Add username and password
            form_data[login_form['username_field']] = username
            form_data[login_form['password_field']] = password
            
            # Add other form fields with default values
            for input_field in login_form['inputs']:
                field_name = input_field['name']
                if (field_name not in form_data and 
                    input_field['type'] not in ['submit', 'button']):
                    form_data[field_name] = input_field['value']
            
            # Submit login form
            if login_form['method'] == 'POST':
                response = self.session.post(login_form['action'], 
                                           data=form_data, timeout=10)
            else:
                response = self.session.get(login_form['action'], 
                                          params=form_data, timeout=10)
            
            # Check if authentication was successful
            success = self.verify_authentication(response, login_form['url'])
            
            if success:
                self.authenticated = True
                self.auth_cookies = dict(self.session.cookies)
                self.logger.info("Form-based authentication successful")
                return True
            else:
                self.logger.warning("Form-based authentication failed")
                return False
                
        except requests.RequestException as e:
            self.logger.error(f"Error during form-based authentication: {e}")
            return False

    def authenticate_basic_auth(self, url: str, username: str, password: str) -> bool:
        """Attempt HTTP Basic Authentication"""
        try:
            response = self.session.get(url, auth=(username, password), timeout=10)
            
            if response.status_code != 401:
                self.authenticated = True
                self.auth_headers['Authorization'] = f'Basic {username}:{password}'
                self.session.headers.update(self.auth_headers)
                self.logger.info("Basic authentication successful")
                return True
            else:
                self.logger.warning("Basic authentication failed")
                return False
                
        except requests.RequestException as e:
            self.logger.error(f"Error during basic authentication: {e}")
            return False

    def authenticate_bearer_token(self, token: str) -> bool:
        """Set Bearer token for API authentication"""
        try:
            self.auth_headers['Authorization'] = f'Bearer {token}'
            self.session.headers.update(self.auth_headers)
            self.authenticated = True
            self.logger.info("Bearer token authentication set")
            return True
        except Exception as e:
            self.logger.error(f"Error setting bearer token: {e}")
            return False

    def verify_authentication(self, response: requests.Response, 
                            original_url: str) -> bool:
        """Verify if authentication was successful"""
        # Check for redirect to dashboard/home page
        if response.url != original_url and response.status_code == 200:
            return True
        
        # Check for success indicators in response content
        success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile', 'settings',
            'authenticated', 'logged in', 'sign out'
        ]
        
        content_lower = response.text.lower()
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        # Check for absence of login form
        soup = BeautifulSoup(response.content, 'html.parser')
        login_forms = self.extract_login_forms(soup, response.url)
        
        # If no login forms found and we got a 200 response, likely authenticated
        if not login_forms and response.status_code == 200:
            return True
        
        return False

    def test_authenticated_access(self, test_urls: List[str]) -> Dict[str, bool]:
        """Test access to protected resources"""
        results = {}
        
        for url in test_urls:
            try:
                response = self.session.get(url, timeout=10)
                # Consider 200 and 3xx as successful access
                results[url] = response.status_code < 400
            except requests.RequestException:
                results[url] = False
        
        return results

    def save_session(self, filepath: str) -> bool:
        """Save authentication session to file"""
        try:
            session_data = {
                'cookies': dict(self.session.cookies),
                'headers': dict(self.session.headers),
                'authenticated': self.authenticated
            }
            
            with open(filepath, 'w') as f:
                json.dump(session_data, f, indent=2)
            
            self.logger.info(f"Session saved to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving session: {e}")
            return False

    def load_session(self, filepath: str) -> bool:
        """Load authentication session from file"""
        try:
            if not os.path.exists(filepath):
                return False
            
            with open(filepath, 'r') as f:
                session_data = json.load(f)
            
            # Restore cookies
            for name, value in session_data.get('cookies', {}).items():
                self.session.cookies.set(name, value)
            
            # Restore headers
            headers = session_data.get('headers', {})
            self.session.headers.update(headers)
            
            self.authenticated = session_data.get('authenticated', False)
            self.auth_cookies = session_data.get('cookies', {})
            
            self.logger.info(f"Session loaded from {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading session: {e}")
            return False

    def get_session_info(self) -> Dict:
        """Get current session information"""
        return {
            'authenticated': self.authenticated,
            'cookies_count': len(self.session.cookies),
            'auth_headers': list(self.auth_headers.keys()),
            'user_agent': self.session.headers.get('User-Agent', '')
        }

    def logout(self, logout_url: Optional[str] = None) -> bool:
        """Attempt to logout from the application"""
        if logout_url:
            try:
                response = self.session.get(logout_url, timeout=10)
                self.logger.info(f"Logout attempted: {response.status_code}")
            except requests.RequestException as e:
                self.logger.error(f"Error during logout: {e}")
        
        # Clear authentication state
        self.authenticated = False
        self.auth_cookies = {}
        self.auth_headers = {}
        self.session.cookies.clear()
        
        # Remove auth headers
        headers_to_remove = ['Authorization']
        for header in headers_to_remove:
            self.session.headers.pop(header, None)
        
        return True

if __name__ == "__main__":
    # Example usage
    auth_manager = AuthenticationManager()
    
    # Find login forms
    login_forms = auth_manager.find_login_forms("http://example.com")
    print(f"Found {len(login_forms)} login forms")
    
    # Test authentication
    if login_forms:
        success = auth_manager.authenticate_form_based(
            login_forms[0], "testuser", "testpass"
        )
        print(f"Authentication successful: {success}")