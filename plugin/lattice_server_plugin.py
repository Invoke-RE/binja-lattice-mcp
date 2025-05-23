from binaryninja import *
from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption
from binaryninja.function import DisassemblySettings, Function 
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.plugin import PluginCommand
from binaryninja.log import Logger
from typing import Optional, Dict, Any, List, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json
import os
import secrets
import time
import ssl
import re
import traceback
import threading

logger = Logger(session_id=0, logger_name=__name__)

class AuthManager:
    """Manages authentication for the Lattice Protocol"""
    def __init__(self, token_expiry_seconds=28800):
        """
        Initialize the authentication manager
        
        Args:
            token_expiry_seconds: How long tokens are valid (default: 1 hour)
        """
        self.token_expiry_seconds = token_expiry_seconds
        self.tokens = {}  # Map of token -> (expiry_time, client_info)
        
        # Generate a secure API key on startup
        self.api_key = secrets.token_hex(16)
        logger.log_info(f"API key: {self.api_key}")
    
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
        logger.log_info(f"Validating token: {token}")
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
    
    def verify_credentials(self, password: str) -> bool:
        """
        Verify a username and password against stored credentials.
        For simplicity, this just verifies against the API key.
        In a real implementation, this would check against a secure credential store.
        
        Args:
            username: The username to tie to session token
            password: The password to verify
            
        Returns:
            True if the credentials are valid, False otherwise
        """
        # For simplicity, we're using the API key as the "password"
        # In a real implementation, this would use secure password hashing
        return password == self.api_key

class LatticeRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Lattice Protocol"""
    
    def __init__(self, *args, **kwargs):
        self.protocol = kwargs.pop('protocol')
        super().__init__(*args, **kwargs)
    
    def _send_response(self, data: Dict[str, Any], status: int = 200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _require_auth(self, handler):
        """Decorator to require authentication"""
        def decorated(*args, **kwargs):
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self._send_response({'status': 'error', 'message': 'No token provided'}, 401)
                return
            
            # Remove 'Bearer ' prefix if present
            token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header
            
            is_valid, client_info = self.protocol.auth_manager.validate_token(token)
            if not is_valid:
                self._send_response({'status': 'error', 'message': 'Invalid token'}, 401)
                return
            
            return handler(*args, **kwargs)
        return decorated
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode())
        except Exception as e:
            self._send_response({'status': 'error', 'message': str(e)}, 400)
            return
        
        if path == '/auth':
            self._handle_auth(data)
        elif path.startswith('/comments/'):
            self._require_auth(self._handle_add_comment_to_address)(data)
        elif path.startswith('/functions/'):
            logger.log_info(f"Handling add comment to function request: {data}")
            self._require_auth(self._handle_add_comment_to_function)(data)
        else:
            self._send_response({'status': 'error', 'message': 'Invalid endpoint'}, 404)
    
    def do_PUT(self):
        """Handle PUT requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode())
        except Exception as e:
            self._send_response({'status': 'error', 'message': str(e)}, 400)
            return
        
        if path.startswith('/functions/') and path.endswith('/name'):
            self._require_auth(self._handle_update_function_name)(data)
        elif path.startswith('/variables/') and path.endswith('/name'):
            self._require_auth(self._handle_update_variable_name)(data)
        else:
            self._send_response({'status': 'error', 'message': 'Invalid endpoint'}, 404)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/binary/info':
            self._require_auth(self._handle_get_binary_info)()
        elif path == '/functions':
            self._require_auth(self._handle_get_all_function_names)()
        elif path.startswith('/functions/'):
            if path.startswith('/functions/name/'):
                self._require_auth(self._handle_get_function_context_by_name)()
            elif path.endswith('/disassembly'):
                self._require_auth(self._handle_get_function_disassembly)()
            elif path.endswith('/pseudocode'):
                self._require_auth(self._handle_get_function_pseudocode)()
            elif path.endswith('/variables'):
                self._require_auth(self._handle_get_function_variables)()
            else:
                self._require_auth(self._handle_get_function_context_by_address)()
        elif path.startswith('/global_variable_data'):
            self._require_auth(self._handle_get_global_variable_data)()
        elif path.startswith('/cross-references/'):
            self._require_auth(self._handle_get_cross_references_to_function)()
        else:
            self._send_response({'status': 'error', 'message': 'Invalid endpoint'}, 404)
    
    def _handle_auth(self, data):
        """Handle authentication requests"""
        username = data.get('username')
        password = data.get('password')
        token = data.get('token')
        
        if token:
            is_valid, client_info = self.protocol.auth_manager.validate_token(token)
            if is_valid:
                self._send_response({
                    'status': 'success',
                    'message': 'Authentication successful',
                    'token': token
                })
                return
        
        if password:
            if self.protocol.auth_manager.verify_credentials(password):
                client_info = {'username': username, 'address': self.client_address[0]}
                new_token = self.protocol.auth_manager.generate_token(client_info)
                self._send_response({
                    'status': 'success',
                    'message': 'Authentication successful',
                    'token': new_token
                })
                return
        
        self._send_response({'status': 'error', 'message': 'Authentication failed'}, 401)
    
    def _handle_get_binary_info(self):
        """Handle requests for binary information"""
        try:
            binary_info = {
                'filename': self.protocol.bv.file.filename,
                'file_size': self.protocol.bv.end,
                'start': self.protocol.bv.start,
                'end': self.protocol.bv.end,
                'entry_point': self.protocol.bv.entry_point,
                'arch': self.protocol.bv.arch.name,
                'platform': self.protocol.bv.platform.name,
                'segments': self.protocol._get_segments_info(),
                'sections': self.protocol._get_sections_info(),
                'functions_count': len(self.protocol.bv.functions),
                'symbols_count': len(self.protocol.bv.symbols)
            }
            
            self._send_response({
                'status': 'success',
                'binary_info': binary_info
            })
            
        except Exception as e:
            logger.log_error(f"Error getting binary info: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _get_function_context(self, address: int) -> Dict[str, Any]:
        res = self.protocol.bv.get_functions_containing(address)
        func = None
        if len(res) > 0:
            func = res[0]
        else:
            return None
        
        function_info = {
            'name': func.name,
            'start': func.address_ranges[0].start,
            'end': func.address_ranges[0].end,
            'pseudo_c': self._get_pseudo_c_text(self.protocol.bv, func),
            'call_sites': self._get_call_sites(func),
            'basic_blocks': self._get_basic_blocks_info(func),
            'parameters': self._get_parameters(func),
            'variables': self._get_variables(func),
            'global_variables': self._get_global_variables(),
            'disassembly': self._get_disassembly(func),
            'incoming_calls': self._get_incoming_calls(func)
        }
        return function_info

    def _handle_get_function_context_by_address(self):
        """Handle requests for function context"""
        try:
            address = int(self.path.split('/')[-1], 0)
            function_info = self._get_function_context(address)
            if function_info is None:
                self._send_response({'status': 'error', 'message': f'No function found at address 0x{address:x}'}, 404)
                return
            
            self._send_response({
                'status': 'success',
                'function': function_info
            })
            
        except Exception as e:
            logger.log_error(f"Error getting function context: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)
    
    def _handle_get_function_context_by_name(self):
        """Handle requests for function context by name"""
        try:
            name = self.path.split('/')[-1]
            res = self.protocol.bv.get_functions_by_name(name)
            func = None
            if len(res) > 0:
                func = res[0]
            else:
                self._send_response({'status': 'error', 'message': f'No function found with name: {name}'}, 404)
                return
            
            function_info = self._get_function_context(func.start)
            if function_info is None:
                self._send_response({'status': 'error', 'message': f'No function found with name: {name}'}, 404)
                return
            self._send_response({
                'status': 'success',
                'function': function_info
            })
        except Exception as e:
            logger.log_error(f"Error getting function context by name: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)
    
    def _handle_get_all_function_names(self):
        """Handle requests for all function names"""
        try:
            function_names = [{'name': func.name, 'address': func.start} for func in self.protocol.bv.functions]
            self._send_response({
                'status': 'success',
                'function_names': function_names
            })
        except Exception as e:
            logger.log_error(f"Error getting all function names: {e}")
            self._send_response({'status': 'error', 'message': str(e)}, 500)
    
    def _handle_update_function_name(self, data):
        """Handle requests to update function name"""
        try:
            if not data or 'name' not in data:
                self._send_response({'status': 'error', 'message': 'New name is required'}, 400)
                return
            
            new_name = data['name']
            name = self.path.split('/')[-2]
            func = self._get_function_by_name(name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found with name {name}'}, 404)
                return
            
            old_name = func.name
            func.name = new_name
            
            self._send_response({
                'status': 'success',
                'message': f'Function name updated from "{old_name}" to "{new_name}"'
            })
            
        except Exception as e:
            logger.log_error(f"Error updating function name: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_update_variable_name(self, data):
        """Handle requests to update variable name"""
        try:
            if not data or 'name' not in data:
                self._send_response({'status': 'error', 'message': 'New name is required'}, 400)
                return
            
            new_name = data['name']
            func_name = self.path.split('/')[-3]
            func = self._get_function_by_name(func_name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found at address {func_name}'}, 404)
                return

            # Find the variable by name
            for var in func.vars:
                if var.name == self.path.split('/')[-2]:
                    old_name = var.name
                    var.name = new_name
                    self._send_response({
                        'status': 'success',
                        'message': f'Variable name updated from "{old_name}" to "{new_name}"'
                    })
                    return
            """
                We need to handle the case where the LLM is trying to change
                the name of a global variable. We need to find the global and
                rename it.
            """
            for var in self._get_globals_from_func(func):
                current_var_name = self.path.split('/')[-2]
                if var['name'] == current_var_name:
                    for addr, gvar in self.protocol.bv.data_vars.items():
                        if addr == var['location']:
                            gvar.name = new_name
                            self._send_response({
                                'status': 'success',
                                'message': f'Variable name updated from "{current_var_name}" to "{new_name}"'
                            })
                            return
            
            self._send_response({'status': 'error', 'message': f'No variable with name {self.path.split("/")[-1]} found in function'}, 404)
            
        except Exception as e:
            logger.log_error(f"Error updating variable name: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_global_variable_data(self):
        """Handle requests access data from a global address"""
        try:
            func_name = self.path.split('/')[-2]
            func = self._get_function_by_name(func_name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found at address {func_name}'}, 404)
                return
            # Find the variable by name
            global_name = self.path.split('/')[-1]
            """
                We need to handle the case where the LLM is trying to change
                the name of a global variable. We need to find the global and
                rename it.
            """
            for var in self._get_globals_from_func(func):
                if var['name'] == global_name:
                    for addr, gvar in self.protocol.bv.data_vars.items():
                        if addr == var['location']:
                            read_address = None
                            rbytes = None
                            if gvar.value:
                                target_val = gvar.value
                                # Getting the .value for a value found with heuristics
                                # will actually return this value. If it's an int
                                # then it's likely a pointer for us to follow.
                                if isinstance(target_val, bytes):
                                    rbytes = target_val
                                elif isinstance(target_val, int):
                                    read_address = target_val
                            else:
                                read_address = addr

                            # If there is not a defined value at address, then read
                            # an arbitrary amount of data as a last ditch effort.
                            if read_address and not rbytes:
                                rbytes = self.protocol.bv.read(read_address, 256)
                            self._send_response({
                                'status': 'success',
                                'message': f'Byte slice from global: {rbytes}'
                            })
                            return
        except Exception as e:
            logger.log_error(f"Error updating variable name: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_add_comment_to_address(self, data):
        """Handle requests to add a comment to an address"""
        try:
            if not data or 'comment' not in data:
                self._send_response({'status': 'error', 'message': 'Comment text is required'}, 400)
                return
            
            comment = data['comment']
            self.protocol.bv.set_comment_at(int(self.path.split('/')[-1], 0), comment)
            
            self._send_response({
                'status': 'success',
                'message': f'Comment added at address 0x{int(self.path.split("/")[-1], 0):x}'
            })
            
        except Exception as e:
            logger.log_error(f"Error adding comment: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_add_comment_to_function(self, data):
        """Handle requests to add a comment to a function"""
        try:
            if not data or 'comment' not in data:
                self._send_response({'status': 'error', 'message': 'Comment text is required'}, 400)
                return
            
            comment = data['comment']
            name = self.path.split('/')[-2]
            func = self._get_function_by_name(name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found with name: {name}'}, 404)
                return
            self.protocol.bv.set_comment_at(func.start, comment)
            
            self._send_response({
                'status': 'success',
                'message': f'Comment added to function {name}'
            })
            
        except Exception as e:
            logger.log_error(f"Error adding comment: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _get_function_by_name(self, name):
        """Acquire function by name instead of address"""
        logger.log_info(f"Getting function by name: {name}")
        res = self.protocol.bv.get_functions_by_name(name)
        # TODO: is there a scenario where there's more than one with the same name?
        if len(res) > 0:
            return res[0]
        else:
            return None

    def _get_function_by_address(self, address):
        """Acquire function by address instead of name"""
        res = self.protocol.bv.get_functions_containing(address)
        if res:
            return res[0]
        else:
            return None
    
    def _handle_get_function_disassembly(self):
        """Handle requests for function disassembly with function name"""
        try:
            name = self.path.split('/')[-2]
            func = self._get_function_by_name(name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found with name: {name}'}, 404)
                return
            else:
                disassembly = self._get_disassembly(func)
                self._send_response({
                    'status': 'success',
                    'disassembly': disassembly
                })
        except Exception as e:
            logger.log_error(f"Error getting function disassembly: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)
    
    def _handle_get_function_pseudocode(self):
        """Handle requests for function pseudocode with function name"""
        try:
            name = self.path.split('/')[-2]
            func = self._get_function_by_name(name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found with name: {name}'}, 404)
                return
            
            pseudocode = self._get_pseudo_c_text(self.protocol.bv, func)
            
            self._send_response({
                'status': 'success',
                'pseudocode': pseudocode
            })
            
        except Exception as e:
            logger.log_error(f"Error getting function pseudocode: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)
    
    def _is_global_ptr(self, obj):
        """Callback to look for a HighLevelILConstPtr in instruction line"""
        if(isinstance(obj, HighLevelILConstPtr)):
            return obj

    def _get_globals_from_func(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
        """Get global variables in a given HLIL function"""
        res = []
        gvar_results = []
        """
            We enumerate all instructions in basic blocks to find
            pointers to global variables. We recursively enumerate
            each instruction line for HighLevelILConstPtr to do this.
        """
        for bb in func.hlil:
            for instr in bb:
                res += (list(instr.traverse(self._is_global_ptr)))

        """
            Once we find a pointer, we get the pointer's address value
            and find the data variable that this corresponds to in
            order to find the variable's name. Unnamed variables
            in the format of data_[address] return None for their name
            so we need to format this ourselves to match the pseudocode
            output.
        """
        for r in res:
            address = r.constant
            for gaddr, gvar in self.protocol.bv.data_vars.items():
                if address == gaddr:
                    var_name = None
                    if not gvar.name:
                        var_name = f"data_{address:2x}"
                    else:
                        var_name = gvar.name
                    gvar_results.append({
                        'name': var_name,
                        'type': str(gvar.type),
                        'location': gaddr
                    })
        return gvar_results

    def _handle_get_function_variables(self):
        """Handle requests for function variables"""
        try:
            name = self.path.split('/')[-2]
            func = self._get_function_by_name(name)
            if not func:
                self._send_response({'status': 'error', 'message': f'No function found with name {name}'}, 404)
                return
            
            variables = {
                'parameters': self._get_parameters(func),
                'local_variables': self._get_variables(func),
                'global_variables': self._get_globals_from_func(func)
            }
            
            self._send_response({
                'status': 'success',
                'variables': variables
            })
            
        except Exception as e:
            logger.log_error(f"Error getting function variables: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_cross_references_to_function(self):
        """Handle requests for cross references to a function by address or name"""
        try:
            val = self.path.split('/')[-1]
            logger.log_info(f"Getting cross references to function: {val}")
            if val.startswith('0x'):
                val = int(val, 0)
                func = self._get_function_by_address(val)
            else:
                func = self._get_function_by_name(val)
            if func is None:
                self._send_response({'status': 'error', 'message': f'No function found with name {val}'}, 404)
                return
            cross_references = self._get_cross_references_to_function(func.name)
            if len(cross_references) == 0:
                self._send_response({'status': 'error', 'message': f'No cross references found for function {name}'}, 404)
            self._send_response({
                'status': 'success',
                'cross_references': cross_references
            })
        except Exception as e:
            logger.log_error(f"Error getting cross references to function: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)
    
    def _get_llil_text(self, func: binaryninja.function.Function) -> List[str]:
        """Get LLIL text for a function"""
        result = []
        for block in func.llil:
            for instruction in block:
                result.append({'address': instruction.address, 'text': str(instruction)})
        return result
    
    def _get_mlil_text(self, func: binaryninja.function.Function) -> List[str]:
        """Get MLIL text for a function"""
        result = []
        for block in func.mlil:
            for instruction in block:
                result.append({'address': instruction.address, 'text': str(instruction)})
        return result
    
    def _get_hlil_text(self, func: binaryninja.function.Function) -> List[str]:
        """Get HLIL text for a function"""
        result = []
        for block in func.hlil:
            for instruction in block:
                result.append({'address': instruction.address, 'text': str(instruction)})
        return result

    def _get_pseudo_c_text(self, bv: BinaryView, function: Function) -> List[str]:
        """
        Get pseudo-c text for a function, big thanks to Asher Devila L.
        for help with this https://github.com/AsherDLL/PCDump-bn/blob/main/__init__.py
        """
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
                    addr = int("0x" + lr[0][0], 0)
                    pseudo_c = lr[0][1]
                    result.append({'address': addr, 'text': pseudo_c})
            return result
    
    def _get_call_sites(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
        """Get call sites within a function"""
        result = []
        for ref in func.call_sites:
            called_func = self.protocol.bv.get_function_at(ref.address)
            called_name = called_func.name if called_func else "unknown"
            result.append({
                'address': ref.address,
                'target': called_name
            })
        return result
    
    def _get_cross_references_to_function(self, name: str) -> List[Dict[str, Any]]:
        """
        Get cross references to a function by name.
        This returns functions containing cross-reference locations,
        instead of the actual cross-reference locations.
        """
        result = []
        func = self._get_function_by_name(name)
        if not func:
            return []
        for ref in self.protocol.bv.get_code_refs(func.start):
            called_func = self.protocol.bv.get_functions_containing(ref.address)[0]
            result.append({
                'address': ref.address,
                'function': called_func.name
            })
        return result

    def _get_basic_blocks_info(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
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
    
    def _get_parameters(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
        """Get information about function parameters"""
        result = []
        for param in func.parameter_vars:
            result.append({
                'name': param.name,
                'type': str(param.type),
                'location': str(param.storage)
            })
        return result
    
    def _get_variables(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
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

    def _get_global_variables(self) -> List[Dict[str, Any]]:
        """Get information about global variables"""
        result = []
        for address, var in self.protocol.bv.data_vars.items():
            result.append({
                'name': var.name,
                'type': str(var.type),
                'location': address
            })
        return result
    
    def _get_disassembly(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
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
                    'text': str(instruction)
                })
        return result
    
    def _get_incoming_calls(self, func: binaryninja.function.Function) -> List[Dict[str, Any]]:
        """Get incoming calls to a function"""
        result = []
        for ref in self.protocol.bv.get_code_refs(func.start):
            caller = self.protocol.bv.get_function_at(ref.address)
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
        self.auth_manager = AuthManager()
        self.server = None
    
    def start_server(self):
        """Start the HTTP server"""
        try:
            if self.use_ssl:
                logger.log_info("Starting server with SSL")
                cert_file = os.path.join(os.path.dirname(__file__), "server.crt")
                key_file = os.path.join(os.path.dirname(__file__), "server.key")
                
                self.server = HTTPServer((self.host, self.port), 
                    lambda *args, **kwargs: LatticeRequestHandler(*args, protocol=self, **kwargs))
                self.server.socket = ssl.wrap_socket(self.server.socket,
                    server_side=True,
                    certfile=cert_file,
                    keyfile=key_file)
            else:
                self.server = HTTPServer((self.host, self.port),
                    lambda *args, **kwargs: LatticeRequestHandler(*args, protocol=self, **kwargs))
            
            # Run server in a separate thread
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            logger.log_info(f"Server started on {self.host}:{self.port}")
            logger.log_info(f"Authentication API key: {self.auth_manager.api_key}")
            logger.log_info(f"Use this key to authenticate clients")
            
        except Exception as e:
            logger.log_error(f"Failed to start server: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self.stop_server()
    
    def stop_server(self):
        """Stop the server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.log_info("Server stopped")
    
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

protocol_instances = {}

def register_plugin_command(view):
    protocol = BinjaLattice(view, use_ssl=False)
    protocol.start_server()
    protocol_instances[view] = protocol
    return protocol

def stop_lattice_protocol_server(view):
    protocol = protocol_instances.get(view)
    if protocol:
        protocol.stop_server()
        del protocol_instances[view]

PluginCommand.register(
    "Start Lattice Protocol Server",
    "Start server for Binary Ninja Lattice protocol with authentication",
    register_plugin_command
)

PluginCommand.register(
    "Stop Lattice Protocol Server",
    "Stop server for Binary Ninja Lattice protocol",
    stop_lattice_protocol_server
)
