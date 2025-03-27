from binaryninja import *
from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption
from binaryninja.function import DisassemblySettings, Function 
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.plugin import PluginCommand
import json
import socket
import threading
import logging
import os
import secrets
import time
import ssl
from typing import Optional, Dict, Any, List, Tuple
import re
import traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthManager:
    """Manages authentication for the Lattice Protocol"""
    """Should we fix this 3600 by default? What if the analysis takes longer than 1 hour?"""
    def __init__(self, token_expiry_seconds=3600):
        """
        Initialize the authentication manager
        
        Args:
            token_expiry_seconds: How long tokens are valid (default: 1 hour)
        """
        self.token_expiry_seconds = token_expiry_seconds
        self.tokens = {}  # Map of token -> (expiry_time, client_info)
        
        # Generate a secure API key on startup
        self.api_key = secrets.token_hex(16)
        logger.info(f"Generated API key: {self.api_key}")
    
    def generate_token(self, client_info: Dict[str, Any]) -> str:
        """
        Generate a new authentication token
        
        Args:
            client_info: Information about the client requesting the token
            
        Returns:
            A new authentication token
        """
        token = secrets.token_hex(16)
        expiry = time.time() + self.token_expiry_seconds
        self.tokens[token] = (expiry, client_info)
        
        # Cleanup expired tokens
        self._cleanup_expired_tokens()
        
        return token
    
    def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate an authentication token
        
        Args:
            token: The token to validate
            
        Returns:
            Tuple of (is_valid, client_info)
        """
        logger.info(f"Validating token: {token}")
        if token not in self.tokens:
            return False, None
        
        expiry, client_info = self.tokens[token]
        
        if time.time() > expiry:
            # Token has expired
            del self.tokens[token]
            return False, None
        
        return True, client_info
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token
        
        Args:
            token: The token to revoke
            
        Returns:
            True if the token was revoked, False if it didn't exist
        """
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False
    
    def _cleanup_expired_tokens(self):
        """Remove expired tokens from the tokens dictionary"""
        current_time = time.time()
        expired_tokens = [
            token for token, (expiry, _) in self.tokens.items() 
            if current_time > expiry
        ]
        
        for token in expired_tokens:
            del self.tokens[token]
    
    def verify_credentials(self, username: str, password: str) -> bool:
        """
        Verify a username and password against stored credentials.
        For simplicity, this just verifies against the API key.
        In a real implementation, this would check against a secure credential store.
        
        Args:
            username: The username to verify
            password: The password to verify
            
        Returns:
            True if the credentials are valid, False otherwise
        """
        # For simplicity, we're using the API key as the "password"
        # In a real implementation, this would use secure password hashing
        return password == self.api_key

class BinjaLattice:
    """
    Protocol for communicating between Binary Ninja an external MCP Server or tools.
    This protocol handles sending context from Binary Ninja to MCP Server and receiving
    responses to integrate back into the Binary Ninja UI.
    """
    
    def __init__(self, bv: BinaryView, port: int = 9000, host: str = "localhost", use_ssl: bool = False):
        """
        Initialize the model context protocol.
        
        Args:
            bv: BinaryView object representing the currently analyzed binary
            port: Port number for communication
            host: Host address for the server
            use_ssl: Whether to use SSL/TLS encryption
        """
        self.bv = bv
        self.port = port
        self.host = host
        self.use_ssl = use_ssl
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.clients = []
        self.auth_manager = AuthManager()
        
    def start_server(self):
        """Start the server to listen for model connections"""
        if self.running:
            logger.warning("Server is already running")
            return
            
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            if self.use_ssl:
                # Configure SSL context
                self._setup_ssl()
            
            logger.info(f"Server started on {self.host}:{self.port}")
            logger.info(f"Authentication API key: {self.auth_manager.api_key}")
            logger.info(f"Use this key to authenticate clients")
            
            self.server_thread = threading.Thread(target=self._accept_connections)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            self.stop_server()
    
    def _setup_ssl(self):
        """Set up SSL/TLS for the server"""
        # In a real implementation, use proper certificates
        # For development, we generate a self-signed certificate
        try:
            cert_file = os.path.join(os.path.dirname(__file__), "server.crt")
            key_file = os.path.join(os.path.dirname(__file__), "server.key")
            
            # Check if cert and key files exist, generate if not
            if not (os.path.exists(cert_file) and os.path.exists(key_file)):
                self._generate_self_signed_cert(cert_file, key_file)
            
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            
            logger.info("SSL/TLS configured successfully")
        except Exception as e:
            logger.error(f"Failed to configure SSL/TLS: {e}")
            self.use_ssl = False
    
    def _generate_self_signed_cert(self, cert_file, key_file):
        """Generate self-signed certificate for development purposes"""
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "Locality"
        cert.get_subject().O = "BinjaLattice"
        cert.get_subject().OU = "BinjaLattice Server"
        cert.get_subject().CN = self.host
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Write to disk
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        logger.info(f"Self-signed certificate generated at {cert_file}")
    
    def _accept_connections(self):
        """Accept incoming connections from models"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                logger.info(f"New connection from {addr}")
                
                if self.use_ssl:
                    try:
                        client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                        logger.info(f"SSL/TLS handshake completed with {addr}")
                    except ssl.SSLError as e:
                        logger.error(f"SSL/TLS handshake failed with {addr}: {e}")
                        client_socket.close()
                        continue
                
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
                self.clients.append((client_socket, client_thread))
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket, addr):
        """Handle communication with a connected model client"""
        authenticated = False
        auth_token = None
        
        try:
            # First, handle authentication
            auth_data = self._receive_data(client_socket)
            if not auth_data:
                return
            
            auth_request = json.loads(auth_data)
            if auth_request.get('type') != 'authenticate':
                logger.warning(f"Client {addr} sent a non-authentication request first, closing connection")
                return
            
            # Check credentials
            username = auth_request.get('username')
            password = auth_request.get('password')
            token = auth_request.get('token')
            
            if token:
                # Token-based auth
                authenticated, client_info = self.auth_manager.validate_token(token)
                if authenticated:
                    auth_token = token
                    logger.info(f"Client {addr} authenticated with token")
            elif username and password:
                # Username/password auth
                authenticated = self.auth_manager.verify_credentials(username, password)
                if authenticated:
                    client_info = {'username': username, 'address': addr}
                    auth_token = self.auth_manager.generate_token(client_info)
                    logger.info(f"Client {addr} authenticated with username/password")
            
            # Send authentication response
            auth_response = {
                'status': 'success' if authenticated else 'error',
                'message': 'Authentication successful' if authenticated else 'Authentication failed',
            }
            
            if authenticated:
                auth_response['token'] = auth_token
            
            self._send_data(client_socket, json.dumps(auth_response))
            
            if not authenticated:
                logger.warning(f"Authentication failed for client {addr}, closing connection")
                return
            
            # Now handle regular requests
            while self.running:
                data = self._receive_data(client_socket)
                if not data:
                    break
                    
                request = json.loads(data)
                
                # Make sure token is included and valid in each request
                request_token = request.get('token')
                if not request_token or request_token != auth_token:
                    response = {'status': 'error', 'message': 'Invalid or missing token'}
                else:
                    response = self._process_request(request)
                
                self._send_data(client_socket, json.dumps(response))
                
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            logger.info(f"Connection closed with {addr}")
    
    def _receive_data(self, client_socket) -> Optional[str]:
        """Receive data from the client with proper message framing"""
        try:
            # First receive the message length (4 bytes)
            length_bytes = client_socket.recv(4)
            if not length_bytes:
                return None
                
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Now receive the actual message
            chunks = []
            bytes_received = 0
            
            while bytes_received < message_length:
                chunk = client_socket.recv(min(4096, message_length - bytes_received))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_received += len(chunk)
                
            return b''.join(chunks).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None
    
    def _send_data(self, client_socket, data: str) -> bool:
        """Send data to the client with proper message framing"""
        try:
            message_bytes = data.encode('utf-8')
            message_length = len(message_bytes)
            
            # Send the message length first (4 bytes)
            client_socket.sendall(message_length.to_bytes(4, byteorder='big'))
            
            # Send the actual message
            client_socket.sendall(message_bytes)
            return True
            
        except Exception as e:
            logger.error(f"Error sending data: {e}")
            return False
        
    def _handle_get_all_function_names(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to get all function names"""
        try:
            function_names = [func.name for func in self.bv.functions]
            return {'status': 'success', 'function_names': function_names}
        except Exception as e:
            logger.error(f"Error getting all function names: {e}")
            return {'status': 'error', 'message': str(e)}
        
    def _handle_get_function_context_by_name(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to get function context by name"""
        try:
            function_name = request.get('function_name')
            if function_name is None:
                return {'status': 'error', 'message': 'Function name is required'}  
            func = self.bv.get_function_by_name(function_name)
            if func is None:
                return {'status': 'error', 'message': f'No function found with name: {function_name}'}
            request['address'] = func.start
            return self._handle_function_context_request(request)
        except Exception as e:
            logger.error(f"Error getting function context by name: {e}")
            return {'status': 'error', 'message': str(e)}

    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a request from a model client"""
        request_type = request.get('type')
        
        if request_type == 'get_function_context':
            return self._handle_function_context_request(request)
        elif request_type == 'get_basic_block_context':
            return self._handle_basic_block_context_request(request)
        elif request_type == 'update_function_name':
            return self._handle_update_function_name(request)
        elif request_type == 'update_variable_name':
            return self._handle_update_variable_name(request)
        elif request_type == 'add_comment':
            return self._handle_add_comment(request)
        elif request_type == 'get_binary_info':
            return self._handle_get_binary_info(request)
        elif request_type == 'get_all_function_names':
            return self._handle_get_all_function_names(request)
        elif request_type == 'get_function_context_by_name':
            return self._handle_get_function_context_by_name(request)
        elif request_type == 'get_function_disassembly':
            return self._handle_get_function_disassembly(request)
        elif request_type == 'get_function_pseudocode':
            return self._handle_get_function_pseudocode(request)
        elif request_type == 'get_function_variables':
            return self._handle_get_function_variables(request)
        else:
            return {'status': 'error', 'message': f'Unknown request type: {request_type}'}
    
    def _handle_function_context_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request for function context"""
        try:
            logger.info("Starting function context request handling")
            address = request.get('address')
            if address is None:
                logger.info("No address provided in request")
                return {'status': 'error', 'message': 'Address is required'}
            
            logger.info(f"Looking for function containing address 0x{address:x}")
            func = self.bv.get_functions_containing(address)[0]
            if func is None:
                logger.info(f"No function found at address 0x{address:x}")
                return {'status': 'error', 'message': f'No function found at address 0x{address:x}'}
            
            logger.info(f"Found function: {func.name} at 0x{func.start:x}")
            
            # Get basic information about the function
            logger.info("Getting function address ranges")
            function_info = {
                'name': func.name,
                'start': func.address_ranges[0].start,
                'end': func.address_ranges[0].end,
            }
            logger.info(f"Function range: 0x{function_info['start']:x} - 0x{function_info['end']:x}")
            
            #logger.info("Getting LLIL representation")
            #function_info['llil'] = self._get_llil_text(func)
            #logger.info(f"Found {len(function_info['llil'])} LLIL instructions")
            
            #logger.info("Getting MLIL representation")
            #function_info['mlil'] = self._get_mlil_text(func)
            #logger.info(f"Found {len(function_info['mlil'])} MLIL instructions")
            
            #logger.info("Getting HLIL representation")
            #function_info['hlil'] = self._get_hlil_text(func)
            #logger.info(f"Found {len(function_info['hlil'])} HLIL instructions")
            
            logger.info("Getting pseudo-C representation")
            function_info['pseudo_c'] = self._get_pseudo_c_text(self.bv, func)
            logger.info(f"Found {len(function_info['pseudo_c'])} pseudo-C lines")
            
            logger.info("Getting call sites")
            function_info['call_sites'] = self._get_call_sites(func)
            logger.info(f"Found {len(function_info['call_sites'])} call sites")
            
            logger.info("Getting basic blocks information")
            function_info['basic_blocks'] = self._get_basic_blocks_info(func)
            logger.info(f"Found {len(function_info['basic_blocks'])} basic blocks")
            
            logger.info("Getting function parameters")
            function_info['parameters'] = self._get_parameters(func)
            logger.info(f"Found {len(function_info['parameters'])} parameters")
            
            logger.info("Getting function variables")
            function_info['variables'] = self._get_variables(func)
            logger.info(f"Found {len(function_info['variables'])} variables")
            
            logger.info("Getting function disassembly")
            function_info['disassembly'] = self._get_disassembly(func)
            logger.info(f"Found {len(function_info['disassembly'])} disassembly lines")
            
            logger.info("Getting incoming calls")
            function_info['incoming_calls'] = self._get_incoming_calls(func)
            logger.info(f"Found {len(function_info['incoming_calls'])} incoming calls")
            
            logger.info("Successfully gathered all function context")
            return {
                'status': 'success',
                'function': function_info
            }
            
        except Exception as e:
            logger.error(f"Error getting function context: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_basic_block_context_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request for basic block context"""
        try:
            address = request.get('address')
            if address is None:
                return {'status': 'error', 'message': 'Address is required'}
            
            func = self.bv.get_function_at(address)
            if func is None:
                return {'status': 'error', 'message': f'No function found at address 0x{address:x}'}
            
            block = func.get_basic_block_at(address)
            if block is None:
                return {'status': 'error', 'message': f'No basic block found at address 0x{address:x}'}
            
            block_info = {
                'start': block.start,
                'end': block.end,
                'disassembly': self._get_block_disassembly(block),
                #'llil': self._get_block_llil(block),
                #'mlil': self._get_block_mlil(block),
                'hlil': self._get_block_hlil(block),
                'incoming_edges': [edge.source.start for edge in block.incoming_edges],
                'outgoing_edges': [edge.target.start for edge in block.outgoing_edges]
            }
            
            return {
                'status': 'success',
                'basic_block': block_info
            }
            
        except Exception as e:
            logger.error(f"Error getting basic block context: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_update_function_name(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to update a function name"""
        try:
            address = request.get('address')
            new_name = request.get('name')
            
            if address is None or new_name is None:
                return {'status': 'error', 'message': 'Address and name are required'}
            
            func = self.bv.get_function_at(address)
            if func is None:
                return {'status': 'error', 'message': f'No function found at address 0x{address:x}'}
            
            old_name = func.name
            func.name = new_name
            
            return {
                'status': 'success',
                'message': f'Function name updated from "{old_name}" to "{new_name}"'
            }
            
        except Exception as e:
            logger.error(f"Error updating function name: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_update_variable_name(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to update a variable name"""
        try:
            function_address = request.get('function_address')
            var_id = request.get('variable_id')
            new_name = request.get('name')
            
            if function_address is None or var_id is None or new_name is None:
                return {'status': 'error', 'message': 'Function address, variable ID, and name are required'}
            
            func = self.bv.get_function_at(function_address)
            if func is None:
                return {'status': 'error', 'message': f'No function found at address 0x{function_address:x}'}
            
            # Find the variable by ID
            for var in func.vars:
                if var.identifier == var_id:
                    old_name = var.name
                    func.create_user_var(var.source_type, var.storage, var.index, var.type, new_name)
                    return {
                        'status': 'success',
                        'message': f'Variable name updated from "{old_name}" to "{new_name}"'
                    }
            
            return {'status': 'error', 'message': f'No variable with ID {var_id} found in function'}
            
        except Exception as e:
            logger.error(f"Error updating variable name: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_add_comment(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to add a comment"""
        try:
            address = request.get('address')
            comment = request.get('comment')
            
            if address is None or comment is None:
                return {'status': 'error', 'message': 'Address and comment are required'}
            
            self.bv.set_comment_at(address, comment)
            
            return {
                'status': 'success',
                'message': f'Comment added at address 0x{address:x}'
            }
            
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_get_binary_info(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to get information about the binary"""
        try:
            binary_info = {
                'filename': self.bv.file.filename,
                'file_size': self.bv.end,
                'start': self.bv.start,
                'end': self.bv.end,
                'entry_point': self.bv.entry_point,
                'arch': self.bv.arch.name,
                'platform': self.bv.platform.name,
                'segments': self._get_segments_info(),
                'sections': self._get_sections_info(),
                'functions_count': len(self.bv.functions),
                'symbols_count': len(self.bv.symbols)
            }
            
            return {
                'status': 'success',
                'binary_info': binary_info
            }
            
        except Exception as e:
            logger.error(f"Error getting binary info: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _get_llil_text(self, func) -> List[str]:
        """Get LLIL text for a function"""
        result = []
        for block in func.llil:
            for instruction in block:
                result.append(f"0x{instruction.address:x}: {instruction}")
        return result
    
    def _get_mlil_text(self, func) -> List[str]:
        """Get MLIL text for a function"""
        result = []
        for block in func.mlil:
            for instruction in block:
                result.append(f"0x{instruction.address:x}: {instruction}")
        return result
    
    def _get_hlil_text(self, func) -> List[str]:
        """Get HLIL text for a function"""
        result = []
        for block in func.hlil:
            for instruction in block:
                result.append(f"0x{instruction.address:x}: {instruction}")
        return result

    def _get_pseudo_c_text(self, bv: BinaryView, function: Function) -> List[str]:
        lines = []
        settings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowAddress, True)
        settings.set_option(DisassemblyOption.WaitForIL, True)
        obj = LinearViewObject.language_representation(bv, settings)
        cursor_end = LinearViewCursor(obj)
        cursor_end.seek_to_address(function.highest_address)
        body = bv.get_next_linear_disassembly_lines(cursor_end)
        cursor_end.seek_to_address(function.highest_address)
        header = bv.get_previous_linear_disassembly_lines(cursor_end)
        for line in header:
            lines.append(f'{str(line)}\n')
        for line in body:
            lines.append(f'{str(line)}\n')
        with_addr = self._get_addr_pseudo_c_from_text(lines)
        return with_addr

    def _get_addr_pseudo_c_from_text(self, lines: list) -> List[str]:
        """Get addresses and pseudo-c from pseudo-c text output"""
        if lines is None:
            return []
        else:
            result = []
            for l in lines:
                lr = re.findall("(^[0-9A-Fa-f]+)(.*)$", l)
                if lr:
                    # Converting binja address format of 0x[Address]
                    addr = int("0x" + lr[0][0], 16)
                    pseudo_c = lr[0][1]
                    result.append(f"0x{addr}: {pseudo_c}")
            return result
    
    def _get_call_sites(self, func) -> List[Dict[str, Any]]:
        """Get call sites within a function"""
        result = []
        for ref in func.call_sites:
            called_func = self.bv.get_function_at(ref.address)
            called_name = called_func.name if called_func else "unknown"
            result.append({
                'address': ref.address,
                'target': called_name
            })
        return result
    
    def _get_basic_blocks_info(self, func) -> List[Dict[str, Any]]:
        """Get information about basic blocks in a function"""
        result = []
        for block in func.basic_blocks:
            result.append({
                'start': block.start,
                'end': block.end,
                'incoming_edges': [edge.source.start for edge in block.incoming_edges],
                'outgoing_edges': [edge.target.start for edge in block.outgoing_edges]
            })
        return result
    
    def _get_parameters(self, func) -> List[Dict[str, Any]]:
        """Get information about function parameters"""
        result = []
        for param in func.parameter_vars:
            result.append({
                'name': param.name,
                'type': str(param.type),
                'location': str(param.storage)
            })
        return result
    
    def _get_variables(self, func) -> List[Dict[str, Any]]:
        """Get information about function variables"""
        result = []
        for var in func.vars:
            result.append({
                'name': var.name,
                'type': str(var.type),
                'location': str(var.storage),
                'id': var.identifier
            })
        return result
    
    def _get_disassembly(self, func) -> List[Dict[str, Any]]:
        """Get disassembly for a function"""
        result = []
        for block in func:
            all_dis = block.get_disassembly_text()
            for i, instruction in enumerate(all_dis):
                if i == len(all_dis)-1:
                    instr_len = block.end-instruction.address
                else:
                    instr_len = all_dis[i+1].address-all_dis[i].address
                result.append({
                    'address': instruction.address,
                    'text': str(instruction),
                    'bytes': [str(hex(b)) for b in self.bv.read(instruction.address, instr_len)],
                    'length': instr_len
                })
        return result
    
    def _get_incoming_calls(self, func) -> List[Dict[str, Any]]:
        """Get incoming calls to a function"""
        result = []
        for ref in self.bv.get_code_refs(func.start):
            caller = self.bv.get_function_at(ref.address)
            if caller:
                result.append({
                    'address': ref.address,
                    'function': caller.name
                })
        return result
    
    def _get_block_disassembly(self, block) -> List[Dict[str, Any]]:
        """Get disassembly for a basic block"""
        result = []
        for instruction in block:
            result.append({
                'address': instruction.address,
                'text': instruction.get_disassembly_text(),
                'bytes': [b for b in instruction.bytes],
                'length': instruction.length
            })
        return result
    
    def _get_block_llil(self, block) -> List[str]:
        """Get LLIL text for a basic block"""
        result = []
        func = block.function
        llil_block = func.get_low_level_il_at(block.start).ssa_form
        if llil_block:
            for instruction in llil_block:
                result.append(f"0x{instruction.address:x}: {instruction}")
        return result
    
    def _get_block_mlil(self, block) -> List[str]:
        """Get MLIL text for a basic block"""
        result = []
        func = block.function
        mlil_block = func.get_medium_level_il_at(block.start).ssa_form
        if mlil_block:
            for instruction in mlil_block:
                result.append(f"0x{instruction.address:x}: {instruction}")
        return result
    
    def _get_block_hlil(self, block) -> List[str]:
        """Get HLIL text for a basic block"""
        result = []
        func = block.function
        hlil_block = func.get_high_level_il_at(block.start).ssa_form
        if hlil_block:
            for instruction in hlil_block:
                result.append(f"0x{instruction.address:x}: {instruction}")
        return result
    
    def _get_segments_info(self) -> List[Dict[str, Any]]:
        """Get information about binary segments"""
        result = []
        for segment in self.bv.segments:
            result.append({
                'start': segment.start,
                'end': segment.end,
                'length': segment.length,
                'permissions': {
                    'read': segment.readable,
                    'write': segment.writable,
                    'execute': segment.executable
                }
            })
        return result
    
    def _get_sections_info(self) -> List[Dict[str, Any]]:
        """Get information about binary sections"""
        result = []
        for section in self.bv.sections.values():
            result.append({
                'name': section.name,
                'start': section.start,
                'end': section.end,
                'length': section.length,
                'semantics': str(section.semantics)
            })
        return result
    
    def _handle_get_function_disassembly(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to get function disassembly"""
        try:
            address = request.get('address')
            if address is None:
                return {'status': 'error', 'message': 'Address is required'}
            
            func = self.bv.get_function_at(address)
            if func is None:
                return {'status': 'error', 'message': f'No function found at address 0x{address:x}'}
            
            disassembly = self._get_disassembly(func)
            
            return {
                'status': 'success',
                'disassembly': disassembly
            }
            
        except Exception as e:
            logger.error(f"Error getting function disassembly: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_get_function_pseudocode(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to get function pseudocode"""
        try:
            address = request.get('address')
            if address is None:
                return {'status': 'error', 'message': 'Address is required'}
            
            func = self.bv.get_function_at(address)
            if func is None:
                return {'status': 'error', 'message': f'No function found at address 0x{address:x}'}
            
            pseudocode = self._get_pseudo_c_text(self.bv, func)
            
            return {
                'status': 'success',
                'pseudocode': pseudocode
            }
            
        except Exception as e:
            logger.error(f"Error getting function pseudocode: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def _handle_get_function_variables(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request to get function variables"""
        try:
            address = request.get('address')
            if address is None:
                return {'status': 'error', 'message': 'Address is required'}
            
            func = self.bv.get_function_at(address)
            if func is None:
                return {'status': 'error', 'message': f'No function found at address 0x{address:x}'}
            
            # Get both parameters and local variables
            variables = {
                'parameters': self._get_parameters(func),
                'local_variables': self._get_variables(func)
            }
            
            return {
                'status': 'success',
                'variables': variables
            }
            
        except Exception as e:
            logger.error(f"Error getting function variables: {e}")
            logger.error("Stack trace: %s", traceback.format_exc())
            return {'status': 'error', 'message': str(e), 'stack_trace': traceback.format_exc()}
    
    def stop_server(self):
        """Stop the server and close all connections"""
        self.running = False
        
        # Close all client connections
        for client_socket, _ in self.clients:
            try:
                client_socket.close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            
        logger.info("Server stopped")

# Example usage as a plugin
def register_plugin_command(view):
    # This now has the option to enable SSL
    protocol = BinjaLattice(view, use_ssl=True)
    protocol.start_server()
    return protocol

# Register plugin
PluginCommand.register(
    "Start Lattice Protocol Server",
    "Start server for Binary Ninja Lattice protocol with authentication",
    register_plugin_command
)

# Example of client usage (see lattice_client.py for client implementation)
"""
from lattice_client import LatticeClient

# Connect to a BinjaLattice server
client = LatticeClient(host="localhost", port=9000, use_ssl=True)
if client.connect():
    # Authenticate with username and password (API key)
    if client.authenticate("user", "generated_api_key_from_server_logs"):
        # Now make requests
        binary_info = client.get_binary_info()
        print(f"Binary: {binary_info.get('binary_info', {}).get('filename')}")
        
        # Get function context at address 0x1000
        function_context = client.get_function_context(0x1000)
        if function_context.get('status') == 'success':
            print(f"Function name: {function_context.get('function', {}).get('name')}")
    
    # Close the connection when done
    client.close()
"""