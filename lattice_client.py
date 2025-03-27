import requests
import json
import logging
import argparse
import sys
from typing import Optional, Dict, Any, List, Tuple, Union
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LatticeClient:
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
            return None
        except Exception as e:
            logger.error(f"Error getting function context: {e}")
            return None

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
            return None
        except Exception as e:
            logger.error(f"Error getting function context by name: {e}")
            return None
    
    def get_all_function_names(self) -> Optional[Dict[str, Any]]:
        """
        Get all function names
        """
        try:
            response = self.session.get(urljoin(self.base_url, '/functions'))
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting all function names: {e}")
            return None
    
    def update_function_name(self, address: int, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a function
        
        Args:
            address: Address of the function
            new_name: New name for the function
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/functions/{address}/name'),
                json={'name': new_name}
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error updating function name: {e}")
            return None
    
    def update_variable_name(self, function_address: int, var_id: int, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a variable in a function
        
        Args:
            function_address: Address of the function containing the variable
            var_id: ID of the variable to rename
            new_name: New name for the variable
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/variables/{function_address}/{var_id}/name'),
                json={'name': new_name}
            )
            if response.status_code == 200:
                return response.json()
            else:
                print(response.text)
            return None
        except Exception as e:
            logger.error(f"Error updating variable name: {e}")
            return None
    
    def add_comment(self, address: int, comment: str) -> Optional[Dict[str, Any]]:
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
            return None
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return None
    
    def get_function_disassembly(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get disassembly for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function disassembly
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{address}/disassembly'))
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting function disassembly: {e}")
            return None

    def get_function_pseudocode(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get pseudocode for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function pseudocode
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{address}/pseudocode'))
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting function pseudocode: {e}")
            return None

    def get_function_variables(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get variables for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function variables
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{address}/variables'))
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting function variables: {e}")
            return None
    
    def close(self):
        """Close the connection to the server"""
        self.session.close()
        logger.info("Connection closed")

def print_menu():
    """Print the interactive menu"""
    print("\nBinjaLattice Client Menu:")
    print("1. Get Binary Information")
    print("2. Get Function Context by Address")
    print("3. Get Function Context by Name")
    print("4. Update Function Name")
    print("5. Update Variable Name")
    print("6. Add Comment")
    print("7. Reconnect to Server")
    print("8. Get All Function Names")
    print("9. Get Function Disassembly")
    print("10. Get Function Pseudocode")
    print("11. Get Function Variables")
    print("12. Exit")
    print()

def interactive_mode(client: LatticeClient):
    """Run the interactive REPL mode"""
    while True:
        print_menu()
        try:
            choice = input("Enter your choice (1-12): ").strip()
            
            if choice == '1':
                result = client.get_binary_info()
                print(json.dumps(result, indent=2))
                
            elif choice == '2':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_context(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '3':
                name = input("Enter function name: ").strip()
                try:
                    result = client.get_function_context_by_name(name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid function name")
                    
            elif choice == '4':
                addr = input("Enter function address (hex or decimal): ").strip()
                new_name = input("Enter new function name: ").strip()
                try:
                    address = int(addr, 0)
                    result = client.update_function_name(address, new_name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
                    
            elif choice == '5':
                func_addr = input("Enter function address (hex or decimal): ").strip()
                var_id = input("Enter variable ID: ").strip()
                new_name = input("Enter new variable name: ").strip()
                try:
                    address = int(func_addr, 0)
                    var_id = int(var_id)
                    result = client.update_variable_name(address, var_id, new_name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid input format")
                    
            elif choice == '6':
                addr = input("Enter address (hex or decimal): ").strip()
                comment = input("Enter comment: ").strip()
                try:
                    address = int(addr, 0)
                    result = client.add_comment(address, comment)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
                    
            elif choice == '7':
                client.close()
                if client.connect():
                    print("Reconnected successfully")
                    if client.auth_token:
                        print("Previous authentication token is still valid")
                else:
                    print("Failed to reconnect")
            elif choice == '8':
                result = client.get_all_function_names()
                print(json.dumps(result, indent=2))
            elif choice == '9':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_disassembly(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '10':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_pseudocode(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '11':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_variables(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '12':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")
            print("Try reconnecting to the server (option 7)")

def main():
    parser = argparse.ArgumentParser(description='BinjaLattice Client - Communicate with Binary Ninja Lattice Protocol Server')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=9000, help='Server port (default: 9000)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS encryption')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--username', help='Username for authentication')
    auth_group.add_argument('--password', help='Password/API key for authentication')
    auth_group.add_argument('--token', help='Authentication token')
    
    # Command options (only used in non-interactive mode)
    command_group = parser.add_argument_group('Commands')
    command_group.add_argument('--get-binary-info', action='store_true', help='Get binary information')
    command_group.add_argument('--get-function-context', type=lambda x: int(x, 0), help='Get function context at address (hex or decimal)')
    command_group.add_argument('--get-basic-block-context', type=lambda x: int(x, 0), help='Get basic block context at address (hex or decimal)')
    command_group.add_argument('--update-function-name', nargs=2, help='Update function name: <address> <new_name>')
    command_group.add_argument('--update-variable-name', nargs=3, help='Update variable name: <function_address> <var_id> <new_name>')
    command_group.add_argument('--add-comment', nargs=2, help='Add comment: <address> <comment>')
    command_group.add_argument('--get-function-disassembly', type=lambda x: int(x, 0), help='Get function disassembly at address (hex or decimal)')
    command_group.add_argument('--get-function-pseudocode', type=lambda x: int(x, 0), help='Get function pseudocode at address (hex or decimal)')
    command_group.add_argument('--get-function-variables', type=lambda x: int(x, 0), help='Get function variables at address (hex or decimal)')
    
    args = parser.parse_args()
    
    # Create client
    client = LatticeClient(host=args.host, port=args.port, use_ssl=args.ssl)
    
    # Authenticate
    if args.token:
        if not client.authenticate_with_token(args.token):
            print("Authentication failed with token")
            client.close()
            sys.exit(1)
    elif args.username and args.password:
        if not client.authenticate(args.username, args.password):
            print("Authentication failed with username/password")
            client.close()
            sys.exit(1)
    else:
        print("Authentication credentials required (--token or --username/--password)")
        client.close()
        sys.exit(1)
    
    try:
        if args.interactive:
            interactive_mode(client)
        else:
            # Execute requested command
            if args.get_binary_info:
                result = client.get_binary_info()
                print(json.dumps(result, indent=2))
                
            elif args.get_function_context:
                result = client.get_function_context(args.get_function_context)
                print(json.dumps(result, indent=2))
            elif args.update_function_name:
                address = int(args.update_function_name[0], 0)
                new_name = args.update_function_name[1]
                result = client.update_function_name(address, new_name)
                print(json.dumps(result, indent=2))
                
            elif args.update_variable_name:
                func_addr = int(args.update_variable_name[0], 0)
                var_id = int(args.update_variable_name[1])
                new_name = args.update_variable_name[2]
                result = client.update_variable_name(func_addr, var_id, new_name)
                print(json.dumps(result, indent=2))
                
            elif args.add_comment:
                address = int(args.add_comment[0], 0)
                comment = args.add_comment[1]
                result = client.add_comment(address, comment)
                print(json.dumps(result, indent=2))
                
            elif args.get_function_disassembly:
                result = client.get_function_disassembly(args.get_function_disassembly)
                print(json.dumps(result, indent=2))
                
            elif args.get_function_pseudocode:
                result = client.get_function_pseudocode(args.get_function_pseudocode)
                print(json.dumps(result, indent=2))
                
            elif args.get_function_variables:
                result = client.get_function_variables(args.get_function_variables)
                print(json.dumps(result, indent=2))
                
            else:
                print("No command specified. Use --help to see available commands.")
                
    finally:
        client.close()

if __name__ == "__main__":
    main() 