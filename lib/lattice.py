import requests
import json
import logging
import sys
from typing import Optional, Dict, Any, List, Tuple, Union
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Lattice:
    """Client for communicating with a BinjaLattice server"""
    
    def __init__(self, host: str = "localhost", port: int = 9000, use_ssl: bool = False):
        """
        Initialize the client.
        
        Args:
            host: Host address of the server
            port: Port number of the server
            use_ssl: Whether to use SSL/TLS encryption
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.auth_token = None
        self.base_url = f"{'https' if use_ssl else 'http'}://{host}:{port}"
        self.session = requests.Session()
        if not use_ssl:
            self.session.verify = False  # Disable SSL verification for non-SSL connections
    
    def connect(self) -> bool:
        """Connect to the server"""
        #try:
        response = self.session.get(urljoin(self.base_url, '/binary/info'))
        if response.status_code == 200:
            logger.info(f"Connected to {self.host}:{self.port}")
            return True
        elif response.status_code == 401:
            logger.error(f"Authentication failed with status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False
        else:
            logger.error(f"Failed to connect: {response.status_code}")
            return False
        #except Exception as e:
        #    logger.error(f"Failed to connect: {e}")
        #    return False
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with the server using username/password
        
        Args:
            username: Username for authentication
            password: Password (API key) for authentication
            
        Returns:
            True if authentication successful, False otherwise
        """
        response = self.session.post(
            urljoin(self.base_url, '/auth'),
            json={
                'username': username,
                'password': password
            }
        )
        
        if response.status_code == 200:
            print(response.content)
            data = json.loads(response.content)
            if data.get('status') == 'success':
                self.auth_token = data.get('token')
                self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
                logger.info("Authentication successful")
                return True
            else:
                logger.error(f"Authentication failed: {data.get('message')}")
        else:
            logger.error(f"Authentication failed with status code: {response.status_code}")
        
        return False
    
    def authenticate_with_token(self, token: str) -> bool:
        """
        Authenticate with the server using a token
        
        Args:
            token: Authentication token
            
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, '/auth'),
                json={'token': token}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    self.auth_token = token
                    self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
                    logger.info("Token authentication successful")
                    return True
                else:
                    logger.error(f"Token authentication failed: {data.get('message')}")
            else:
                logger.error(f"Token authentication failed with status code: {response.status_code}")
            
            return False
            
        except Exception as e:
            logger.error(f"Token authentication error: {e}")
            return False
    
    def get_binary_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the binary"""
        try:
            response = self.session.get(urljoin(self.base_url, '/binary/info'))
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting binary info: {e}")
            return None
    
    def get_function_context(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get context for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function context
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{address}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function context'}
        except Exception as e:
            logger.error(f"Error getting function context: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_function_context_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get context for a function by name
        
        Args:
            name: Name of the function
            
        Returns:
            Dictionary containing function context
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/name/{name}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function context by name'}
        except Exception as e:
            logger.error(f"Error getting function context by name: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_all_function_names(self) -> Optional[Dict[str, Any]]:
        """
        Get all function names
        """
        try:
            response = self.session.get(urljoin(self.base_url, '/functions'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get all function names'}
        except Exception as e:
            logger.error(f"Error getting all function names: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def update_function_name(self, name: str, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a function
        
        Args:
            name: Current name of the function
            new_name: New name for the function
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/functions/{name}/name'),
                json={'name': new_name}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to update function name'}
        except Exception as e:
            logger.error(f"Error updating function name: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def update_variable_name(self, function_name: str, var_name: str, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a variable in a function
        
        Args:
            function_name: Name of the function containing the variable
            var_name: Name of the variable to rename
            new_name: New name for the variable
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/variables/{function_name}/{var_name}/name'),
                json={'name': new_name}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to update variable name'}
        except Exception as e:
            logger.error(f"Error updating variable name: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_global_variable_data(self, function_name: str, global_var_name: str) -> Optional[Dict[str, Any]]:
        """
        Get data for a global variable
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/global_variable_data/{function_name}/{global_var_name}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get global variable data'}
        except Exception as e:
            logger.error(f"Error getting global variable data: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def add_comment_to_address(self, address: int, comment: str) -> Optional[Dict[str, Any]]:
        """
        Add a comment at the specified address
        
        Args:
            address: Address to add the comment at
            comment: Comment text to add
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, f'/comments/{address}'),
                json={'comment': comment}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to add comment'}
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return {'status': 'error', 'message': str(e)}

    def add_comment_to_function(self, name: str, comment: str) -> Optional[Dict[str, Any]]:
        """
        Add a comment to a function with specified function name
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, f'/functions/{name}/comments'),
                json={'comment': comment}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to add comment'}  
        except Exception as e:
            logger.error(f"Error adding comment to function: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_function_disassembly(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get disassembly for a function with specified function name
        
        Args:
            name: Address of the function
            
        Returns:
            Dictionary containing function disassembly
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{name}/disassembly'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function disassembly'}
        except Exception as e:
            logger.error(f"Error getting function disassembly: {e}")
            return {'status': 'error', 'message': str(e)}
        
    def get_cross_references_to_function(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get cross references to a function
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/cross-references/{name}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get cross references to function'}
        except Exception as e:
            logger.error(f"Error getting cross references to function: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_function_pseudocode(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get pseudocode for a function with specified function name
        
        Args:
            name: Name of the function
            
        Returns:
            Dictionary containing function pseudocode
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{name}/pseudocode'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function pseudocode'}
        except Exception as e:
            logger.error(f"Error getting function pseudocode: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_function_variables(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get variables for a function at the specified address
        
        Args:
            name: Name of function 
            
        Returns:
            Dictionary containing function variables
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{name}/variables'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function variables'}
        except Exception as e:
            logger.error(f"Error getting function variables: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def close(self):
        """Close the connection to the server"""
        self.session.close()
        logger.info("Connection closed")
