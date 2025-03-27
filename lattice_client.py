import socket
import json
import ssl
import logging
import argparse
import sys
from typing import Optional, Dict, Any, List, Tuple, Union

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
        self.socket = None
        self.auth_token = None
    
    def connect(self) -> bool:
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with the server using username/password
        
        Args:
            username: Username for authentication
            password: Password (API key) for authentication
            
        Returns:
            True if authentication successful, False otherwise
        """
        if not self.socket:
            logger.error("Not connected to server")
            return False
            
        auth_request = {
            'type': 'authenticate',
            'username': username,
            'password': password
        }
        
        if self._send_data(json.dumps(auth_request)):
            response_data = self._receive_data()
            if response_data:
                response = json.loads(response_data)
                if response.get('status') == 'success':
                    self.auth_token = response.get('token')
                    logger.info("Authentication successful")
                    return True
                else:
                    logger.error(f"Authentication failed: {response.get('message')}")
        
        return False
    
    def authenticate_with_token(self, token: str) -> bool:
        """
        Authenticate with the server using a token
        
        Args:
            token: Authentication token
            
        Returns:
            True if authentication successful, False otherwise
        """
        if not self.socket:
            logger.error("Not connected to server")
            return False
            
        auth_request = {
            'type': 'authenticate',
            'token': token
        }
        
        if self._send_data(json.dumps(auth_request)):
            response_data = self._receive_data()
            if response_data:
                response = json.loads(response_data)
                if response.get('status') == 'success':
                    self.auth_token = token
                    logger.info("Token authentication successful")
                    return True
                else:
                    logger.error(f"Token authentication failed: {response.get('message')}")
        
        return False
    
    def get_binary_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the binary"""
        return self._make_request({'type': 'get_binary_info', 'token': self.auth_token})
    
    def get_function_context(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get context for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function context
        """
        return self._make_request({
            'type': 'get_function_context',
            'address': address,
            'token': self.auth_token
        })

    def get_function_context_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get context for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function context
        """
        return self._make_request({
            'type': 'get_function_context',
            'name': name,
            'token': self.auth_token
        })
    
    def get_all_function_names(self) -> Optional[Dict[str, Any]]:
        """
        Get all function names
        """
        return self._make_request({
            'type': 'get_all_function_names',
            'token': self.auth_token
        })

    def get_basic_block_context(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get context for a basic block at the specified address
        
        Args:
            address: Address within the basic block
            
        Returns:
            Dictionary containing basic block context
        """
        return self._make_request({
            'type': 'get_basic_block_context',
            'address': address,
            'token': self.auth_token
        })
    
    def update_function_name(self, address: int, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a function
        
        Args:
            address: Address of the function
            new_name: New name for the function
            
        Returns:
            Dictionary containing the result of the operation
        """
        return self._make_request({
            'type': 'update_function_name',
            'address': address,
            'name': new_name,
            'token': self.auth_token
        })
    
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
        return self._make_request({
            'type': 'update_variable_name',
            'function_address': function_address,
            'variable_id': var_id,
            'name': new_name,
            'token': self.auth_token
        })
    
    def add_comment(self, address: int, comment: str) -> Optional[Dict[str, Any]]:
        """
        Add a comment at the specified address
        
        Args:
            address: Address to add the comment at
            comment: Comment text to add
            
        Returns:
            Dictionary containing the result of the operation
        """
        return self._make_request({
            'type': 'add_comment',
            'address': address,
            'comment': comment,
            'token': self.auth_token
        })
    
    def get_function_disassembly(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get disassembly for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function disassembly
        """
        return self._make_request({
            'type': 'get_function_disassembly',
            'address': address,
            'token': self.auth_token
        })

    def get_function_pseudocode(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get pseudocode for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function pseudocode
        """
        return self._make_request({
            'type': 'get_function_pseudocode',
            'address': address,
            'token': self.auth_token
        })

    def get_function_variables(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get variables for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function variables
        """
        return self._make_request({
            'type': 'get_function_variables',
            'address': address,
            'token': self.auth_token
        })
    
    def _make_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a request to the server and receive the response"""
        if not self.socket or not self.auth_token:
            logger.error("Not connected or not authenticated")
            return None
        
        if self._send_data(json.dumps(request)):
            response_data = self._receive_data()
            if response_data:
                return json.loads(response_data)
        
        return None
    
    def _send_data(self, data: str) -> bool:
        """
        Send data to the server with proper message framing
        
        Args:
            data: The data to send
            
        Returns:
            True if sending was successful, False otherwise
        """
        try:
            message_bytes = data.encode('utf-8')
            message_length = len(message_bytes)
            
            # Send the message length first (4 bytes)
            self.socket.sendall(message_length.to_bytes(4, byteorder='big'))
            
            # Send the actual message
            self.socket.sendall(message_bytes)
            return True
            
        except Exception as e:
            logger.error(f"Error sending data: {e}")
            return False
    
    def _receive_data(self) -> Optional[str]:
        """
        Receive data from the server with proper message framing
        
        Returns:
            The received data or None if receiving failed
        """
        try:
            # First receive the message length (4 bytes)
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None
                
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Now receive the actual message
            chunks = []
            bytes_received = 0
            
            while bytes_received < message_length:
                chunk = self.socket.recv(min(4096, message_length - bytes_received))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_received += len(chunk)
                
            return b''.join(chunks).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None
    
    def close(self):
        """Close the connection to the server"""
        if self.socket:
            try:
                self.socket.close()
                logger.info("Connection closed")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
            finally:
                self.socket = None
                # Don't clear the token in case we want to reconnect later

def print_menu():
    """Print the interactive menu"""
    print("\nBinjaLattice Client Menu:")
    print("1. Get Binary Information")
    print("2. Get Function Context by Address")
    print("3. Get Function Context by Name")
    print("4. Get Basic Block Context")
    print("5. Update Function Name")
    print("6. Update Variable Name")
    print("7. Add Comment")
    print("8. Reconnect to Server")
    print("9. Get All Function Names")
    print("10. Get Function Disassembly")
    print("11. Get Function Pseudocode")
    print("12. Get Function Variables")
    print("13. Exit")
    print()

def interactive_mode(client: LatticeClient):
    """Run the interactive REPL mode"""
    while True:
        print_menu()
        try:
            choice = input("Enter your choice (1-13): ").strip()
            
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
                addr = input("Enter basic block address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_basic_block_context(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
                    
            elif choice == '5':
                addr = input("Enter function address (hex or decimal): ").strip()
                new_name = input("Enter new function name: ").strip()
                try:
                    address = int(addr, 0)
                    result = client.update_function_name(address, new_name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
                    
            elif choice == '6':
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
                    
            elif choice == '7':
                addr = input("Enter address (hex or decimal): ").strip()
                comment = input("Enter comment: ").strip()
                try:
                    address = int(addr, 0)
                    result = client.add_comment(address, comment)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
                    
            elif choice == '8':
                client.close()
                if client.connect():
                    print("Reconnected successfully")
                    if client.auth_token:
                        print("Previous authentication token is still valid")
                else:
                    print("Failed to reconnect")
            elif choice == '9':
                result = client.get_all_function_names()
                print(json.dumps(result, indent=2))
            elif choice == '10':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_disassembly(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '11':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_pseudocode(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '12':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_variables(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '13':
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
    
    # Connect to server
    if not client.connect():
        print("Failed to connect to server")
        sys.exit(1)
    
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
                
            elif args.get_basic_block_context:
                result = client.get_basic_block_context(args.get_basic_block_context)
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