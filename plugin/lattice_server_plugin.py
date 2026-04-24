from binaryninja import *
from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption
from binaryninja.function import DisassemblySettings, Function
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.plugin import PluginCommand
from binaryninja.log import Logger
from typing import Optional, Dict, Any, List, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import configparser
import socket
import json
import os
import secrets
import time
import ssl
import re
import traceback
import threading

logger = Logger(session_id=0, logger_name=__name__)

class LatticeConfig:
    """Manages config values."""
    def __init__(self, config_filename="config.ini"):
        # Generate a secure API key on startup
        self.new_api_key = secrets.token_hex(16)

        self.config = configparser.ConfigParser()
        plugin_dir = os.path.dirname(os.path.realpath(__file__))
        config_path = os.path.join(plugin_dir, config_filename)

        if os.path.exists(config_path):
            try:
                self.config.read(config_path)
            except Exception as e:
                logger.log_error(f"Error reading config.ini: {e}")
                logger.log_error(f"Using default values")

    def get_host(self, default="127.0.0.1"):
        ip_address = self.config.get("lattice", "ip_address", fallback=default)
        try:
            socket.inet_aton(ip_address)
            self.ip_address = ip_address
        except socket.error:
            logger.log_error(f"Invalid IP Address in config.ini: {ip_address}. Falling back to default (localhost)")
            self.ip_address = default

    def get_port(self, default=9000):
        """Currently only accepting ports between 1024 and 65535 because Binja won't likely have privileges to run on lower ports [1 to 1023]"""

        val = self.config.get("lattice", "port", fallback=str(default))
        try:
            port_int = int(val)
            if 1024 <= port_int <= 65535:
                self.port = port_int
            else:
                logger.log_error(f"Trying to use privileged port: '{val}'. Using default instead: {default}")
                self.port = default
        except ValueError:
            logger.log_error(f"Invalid port '{val}'. Using default {default}")
            self.port = default
            pass

    def get_api_key(self):
        """Uses the config.ini API Key if valid, otherwise, on initialization creates a new one."""
        try:
            api_key_conf = self.config.get("lattice", "api_key")
            self.api_key = api_key_conf.strip() if api_key_conf.strip() else self.new_api_key
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.api_key = self.new_api_key


    def get_use_ssl(self, default=False):
        """Checks if SSL should be used. For configparser everything is a string, so we need to check if the inputs are bools"""
        val = self.config.get("lattice", "use_ssl", fallback=str(default))

        if val == "True":
            self.use_ssl = True
        elif val == "False":
            self.use_ssl = False
        else:
            logger.log_error(f"Value of 'use_ssl' must be either 'True' or 'False'. Got '{val}'.")
            self.use_ssl = default

class AuthManager:
    """Manages authentication for the Lattice Protocol"""
    def __init__(self, config: LatticeConfig, token_expiry_seconds=28800):
        """
        Initialize the authentication manager
        
        Args:
            token_expiry_seconds: How long tokens are valid (default: 1 hour)
        """
        self.token_expiry_seconds = token_expiry_seconds
        self.tokens = {}  # Map of token -> (expiry_time, client_info)
        
        config.get_api_key()
        self.api_key = config.api_key
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
        elif path == '/search/bytes':
            self._require_auth(self._handle_search_bytes)(data)
        elif path == '/types/struct':
            self._require_auth(self._handle_create_struct)(data)
        elif path.startswith('/comments/'):
            self._require_auth(self._handle_add_comment_to_address)(data)
        elif path.startswith('/functions/'):
            logger.log_info(f"Handling add comment to function request: {data}")
            self._require_auth(self._handle_add_comment_to_function)(data)
        elif path == '/tags':
            self._require_auth(self._handle_create_tag)(data)
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
        elif path.startswith('/types/struct/'):
            self._require_auth(self._handle_update_struct)(data)
        elif path.startswith('/functions/') and '/variables/' in path and path.endswith('/type'):
            self._require_auth(self._handle_set_variable_type)(data)
        elif path.startswith('/functions/') and path.endswith('/signature'):
            self._require_auth(self._handle_set_function_signature)(data)
        else:
            self._send_response({'status': 'error', 'message': 'Invalid endpoint'}, 404)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/binary/info':
            self._require_auth(self._handle_get_binary_info)()
        elif path == '/strings':
            self._require_auth(self._handle_get_strings)()
        elif path == '/imports':
            self._require_auth(self._handle_get_imports)()
        elif path == '/exports':
            self._require_auth(self._handle_get_exports)()
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
            elif path.endswith('/callgraph'):
                self._require_auth(self._handle_get_call_graph)()
            else:
                self._require_auth(self._handle_get_function_context_by_address)()
        elif path.startswith('/global_variable_data'):
            self._require_auth(self._handle_get_global_variable_data)()
        elif path.startswith('/cross-references/'):
            self._require_auth(self._handle_get_cross_references_to_function)()
        elif path.startswith('/data/'):
            self._require_auth(self._handle_get_data_at_address)()
        elif path == '/types':
            self._require_auth(self._handle_get_types)()
        elif path == '/tags':
            self._require_auth(self._handle_get_tags)()
        elif path == '/analysis/progress':
            self._require_auth(self._handle_get_analysis_progress)()
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

    def _handle_get_strings(self):
        """Handle requests for strings in the binary with optional filtering"""
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            
            # Get filter parameters
            min_length = int(query_params.get('min_length', ['4'])[0])
            filter_str = query_params.get('filter', [None])[0]
            
            strings_list = []
            for string_ref in self.protocol.bv.get_strings():
                # Apply minimum length filter
                if string_ref.length < min_length:
                    continue
                
                # Apply substring filter (case-insensitive)
                if filter_str and filter_str.lower() not in string_ref.value.lower():
                    continue
                
                strings_list.append({
                    'address': string_ref.start,
                    'value': string_ref.value,
                    'length': string_ref.length
                })
            
            self._send_response({
                'status': 'success',
                'strings': strings_list
            })
            
        except Exception as e:
            logger.log_error(f"Error getting strings: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_imports(self):
        """Handle requests for imported functions in the binary"""
        try:
            imports_list = []
            for sym in self.protocol.bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol):
                # Convert NameSpace to string for JSON serialization
                library = str(sym.namespace) if sym.namespace else ''
                imports_list.append({
                    'name': sym.name,
                    'address': sym.address,
                    'library': library
                })

            self._send_response({
                'status': 'success',
                'imports': imports_list
            })

        except Exception as e:
            logger.log_error(f"Error getting imports: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_exports(self):
        """Handle requests for exported functions in the binary"""
        try:
            exports_list = []
            for sym in self.protocol.bv.get_symbols_of_type(SymbolType.FunctionSymbol):
                if sym.binding == SymbolBinding.GlobalBinding:
                    exports_list.append({
                        'name': sym.name,
                        'address': sym.address
                    })

            self._send_response({
                'status': 'success',
                'exports': exports_list
            })

        except Exception as e:
            logger.log_error(f"Error getting exports: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_data_at_address(self):
        """Handle requests for reading data at a specific address"""
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)

            # Extract address from path: /data/{address}
            path_parts = parsed_path.path.split('/')
            if len(path_parts) < 3:
                self._send_response({'status': 'error', 'message': 'Address required'}, 400)
                return

            # Parse address (supports hex with 0x prefix or decimal)
            addr_str = path_parts[2]
            try:
                if addr_str.startswith('0x') or addr_str.startswith('0X'):
                    address = int(addr_str, 16)
                else:
                    address = int(addr_str)
            except ValueError:
                self._send_response({'status': 'error', 'message': f'Invalid address format: {addr_str}'}, 400)
                return

            # Get query parameters
            length = int(query_params.get('length', ['16'])[0])
            type_name = query_params.get('type', [None])[0]

            # Check if address is readable
            if not self.protocol.bv.is_valid_offset(address):
                self._send_response({
                    'status': 'error',
                    'message': f'Address 0x{address:x} is not readable'
                }, 400)
                return

            # Read raw bytes
            data = self.protocol.bv.read(address, length)
            if data is None:
                self._send_response({
                    'status': 'error',
                    'message': f'Address 0x{address:x} is not readable'
                }, 400)
                return

            # Check if we got less data than requested
            actual_length = len(data)
            truncated = actual_length < length

            response = {
                'status': 'success',
                'address': address,
                'hex': data.hex(),
                'length': actual_length
            }

            if truncated:
                response['warning'] = f'Only {actual_length} bytes available (requested {length})'
                response['truncated'] = True

            # If type is specified, try to interpret the data
            if type_name:
                try:
                    type_obj, _ = self.protocol.bv.parse_type_string(type_name)
                    if type_obj:
                        # Get typed interpretation
                        data_var = self.protocol.bv.get_data_var_at(address)
                        if data_var:
                            response['typed_value'] = str(data_var.value)
                        else:
                            # Try to interpret based on common types
                            response['type'] = type_name
                            response['type_size'] = type_obj.width
                except Exception as type_err:
                    response['type_error'] = f'Could not interpret as {type_name}: {str(type_err)}'

            self._send_response(response)

        except Exception as e:
            logger.log_error(f"Error reading data at address: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_search_bytes(self, data):
        """Handle requests for searching byte patterns in the binary

        Supports hex patterns with optional ?? wildcards for any byte.
        Example patterns: "48 89 5c 24", "48 ?? 5c ??", "488b"
        """
        try:
            pattern = data.get('pattern', '')
            max_results = data.get('max_results', 100)

            if not pattern:
                self._send_response({'status': 'error', 'message': 'Pattern required'}, 400)
                return

            # Parse the hex pattern, handling spaces and wildcards
            pattern_clean = pattern.replace(' ', '').upper()

            # Validate pattern length (must be even number of hex chars)
            if len(pattern_clean) % 2 != 0:
                self._send_response({
                    'status': 'error',
                    'message': 'Invalid pattern: must have even number of hex characters'
                }, 400)
                return

            # Parse pattern into bytes and mask
            pattern_bytes = []
            mask_bytes = []
            has_wildcards = False

            for i in range(0, len(pattern_clean), 2):
                byte_str = pattern_clean[i:i+2]
                if byte_str == '??':
                    pattern_bytes.append(0x00)
                    mask_bytes.append(0x00)  # 0 mask = don't care
                    has_wildcards = True
                else:
                    try:
                        byte_val = int(byte_str, 16)
                        pattern_bytes.append(byte_val)
                        mask_bytes.append(0xFF)  # FF mask = must match
                    except ValueError:
                        self._send_response({
                            'status': 'error',
                            'message': f'Invalid hex byte: {byte_str}'
                        }, 400)
                        return

            pattern_len = len(pattern_bytes)
            results = []
            truncated = False

            if not has_wildcards:
                # Use Binary Ninja's optimized search for exact patterns
                search_bytes = bytes(pattern_bytes)
                bv = self.protocol.bv

                try:
                    for match in bv.find_all_data(bv.start, bv.end, search_bytes):
                        # find_all_data returns tuples of (address, DataBuffer) or just addresses
                        if isinstance(match, tuple):
                            addr = match[0]  # First element is the address
                        elif isinstance(match, int):
                            addr = match
                        elif hasattr(match, 'start'):
                            addr = match.start
                        else:
                            # Skip if we can't determine the address
                            continue
                        results.append({'address': int(addr)})
                        if len(results) >= max_results:
                            truncated = True
                            break
                except Exception as search_err:
                    logger.log_error(f"Error in find_all_data: {search_err}")
                    # Fall back to manual search
                    has_wildcards = True
            else:
                # Manual search with masking for wildcard patterns
                bv = self.protocol.bv

                # Search through all segments
                for segment in bv.segments:
                    if len(results) >= max_results:
                        truncated = True
                        break

                    seg_start = segment.start
                    seg_end = segment.end
                    seg_len = seg_end - seg_start

                    # Read segment data
                    seg_data = bv.read(seg_start, seg_len)
                    if seg_data is None:
                        continue

                    # Search within segment
                    for offset in range(len(seg_data) - pattern_len + 1):
                        if len(results) >= max_results:
                            truncated = True
                            break

                        match = True
                        for j in range(pattern_len):
                            if mask_bytes[j] != 0:  # Only check non-wildcard bytes
                                if seg_data[offset + j] != pattern_bytes[j]:
                                    match = False
                                    break

                        if match:
                            results.append({'address': seg_start + offset})

            # Sort results by address ascending
            results.sort(key=lambda x: x['address'])

            response = {
                'status': 'success',
                'pattern': pattern,
                'results': results,
                'count': len(results)
            }

            if truncated:
                response['truncated'] = True
                response['message'] = f'Results limited to {max_results}'

            self._send_response(response)

        except Exception as e:
            logger.log_error(f"Error searching bytes: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_types(self):
        """Handle requests for defined types in the binary with optional filtering"""
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            
            # Get filter parameter
            filter_str = query_params.get('filter', [None])[0]
            
            types_list = []
            for type_name, type_obj in self.protocol.bv.types.items():
                try:
                    # Convert QualifiedName to string
                    name_str = str(type_name)
                    
                    # Apply name filter (case-insensitive)
                    if filter_str and filter_str.lower() not in name_str.lower():
                        continue
                    
                    type_info = {
                        'name': name_str,
                        'size': type_obj.width if hasattr(type_obj, 'width') else 0
                    }
                    
                    # Determine kind based on type_class
                    type_class = type_obj.type_class if hasattr(type_obj, 'type_class') else None
                    
                    if type_class == TypeClass.StructureTypeClass:
                        type_info['kind'] = 'struct'
                        members = []
                        # Access structure members safely
                        try:
                            struct = type_obj.structure
                            if struct and hasattr(struct, 'members'):
                                for m in struct.members:
                                    members.append({
                                        'name': m.name,
                                        'type': str(m.type),
                                        'offset': m.offset
                                    })
                        except Exception:
                            pass
                        type_info['members'] = members
                    elif type_class == TypeClass.EnumerationTypeClass:
                        type_info['kind'] = 'enum'
                        members = []
                        try:
                            enum = type_obj.enumeration
                            if enum and hasattr(enum, 'members'):
                                for m in enum.members:
                                    members.append({
                                        'name': m.name,
                                        'value': m.value
                                    })
                        except Exception:
                            pass
                        type_info['members'] = members
                    elif type_class == TypeClass.NamedTypeReferenceClass:
                        type_info['kind'] = 'typedef'
                    elif type_class == TypeClass.FunctionTypeClass:
                        type_info['kind'] = 'function'
                    elif type_class == TypeClass.PointerTypeClass:
                        type_info['kind'] = 'pointer'
                    elif type_class == TypeClass.ArrayTypeClass:
                        type_info['kind'] = 'array'
                    else:
                        type_info['kind'] = str(type_class).split('.')[-1].replace('TypeClass', '').lower() if type_class else 'unknown'
                    
                    types_list.append(type_info)
                except Exception as inner_e:
                    # Skip types that cause errors
                    logger.log_warn(f"Skipping type {type_name}: {inner_e}")
                    continue
            
            self._send_response({
                'status': 'success',
                'types': types_list
            })
            
        except Exception as e:
            logger.log_error(f"Error getting types: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_create_struct(self, data):
        """Handle requests to create a new structure type

        Expected JSON body:
        {
            "name": "MyStruct",
            "members": [
                {"name": "field1", "type": "uint32_t"},
                {"name": "field2", "type": "char*", "count": 1}
            ],
            "overwrite": false  # optional, default false
        }
        """
        try:
            name = data.get('name')
            members = data.get('members', [])
            overwrite = data.get('overwrite', False)

            if not name:
                self._send_response({'status': 'error', 'message': 'Structure name is required'}, 400)
                return

            if not members:
                self._send_response({'status': 'error', 'message': 'Structure must have at least one member'}, 400)
                return

            bv = self.protocol.bv

            # Check if structure already exists
            existing_type = None
            for type_name, type_obj in bv.types.items():
                if str(type_name) == name:
                    existing_type = type_obj
                    break

            if existing_type and not overwrite:
                self._send_response({
                    'status': 'error',
                    'message': f"Structure '{name}' already exists. Use overwrite=true to replace."
                }, 409)
                return

            # Validate member types and build structure
            struct_builder = StructureBuilder.create()

            for member in members:
                member_name = member.get('name')
                member_type_str = member.get('type')
                member_count = member.get('count', 1)

                if not member_name or not member_type_str:
                    self._send_response({
                        'status': 'error',
                        'message': 'Each member must have a name and type'
                    }, 400)
                    return

                # Parse the type string
                try:
                    parsed_type, _ = bv.parse_type_string(member_type_str)
                except Exception as e:
                    self._send_response({
                        'status': 'error',
                        'message': f"Member type '{member_type_str}' does not exist or is invalid: {str(e)}"
                    }, 400)
                    return

                # Handle array types
                if member_count > 1:
                    parsed_type = Type.array(parsed_type, member_count)

                struct_builder.append(parsed_type, member_name)

            # Define the structure type
            bv.define_user_type(name, struct_builder.immutable_copy())

            # Retrieve the created structure to return its info
            # Use types dictionary to get the actual type object
            created_type = None
            for type_name, type_obj in bv.types.items():
                if str(type_name) == name:
                    created_type = type_obj
                    break

            if created_type:
                result_members = []
                try:
                    # Check if it's a structure type and get members
                    if hasattr(created_type, 'type_class') and created_type.type_class == TypeClass.StructureTypeClass:
                        struct = created_type.structure
                        if struct and hasattr(struct, 'members'):
                            for m in struct.members:
                                result_members.append({
                                    'name': m.name,
                                    'type': str(m.type),
                                    'offset': m.offset
                                })
                except Exception as member_err:
                    logger.log_warn(f"Could not get structure members: {member_err}")

                self._send_response({
                    'status': 'success',
                    'message': f"Structure '{name}' created successfully",
                    'structure': {
                        'name': name,
                        'size': created_type.width if hasattr(created_type, 'width') else 0,
                        'members': result_members
                    }
                })
            else:
                self._send_response({
                    'status': 'success',
                    'message': f"Structure '{name}' created successfully"
                })

        except Exception as e:
            logger.log_error(f"Error creating structure: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_update_struct(self, data):
        """Handle requests to update an existing structure type

        Expected JSON body:
        {
            "members": [
                {"name": "field1", "type": "uint32_t"},
                {"name": "field2", "type": "char*", "count": 1}
            ]
        }

        The structure name is extracted from the URL path.
        """
        try:
            # Extract structure name from URL path
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            # Path format: /types/struct/{name}
            path_parts = path.split('/')
            if len(path_parts) < 4:
                self._send_response({'status': 'error', 'message': 'Invalid path format'}, 400)
                return

            name = path_parts[3]  # /types/struct/{name}
            members = data.get('members', [])

            if not members:
                self._send_response({'status': 'error', 'message': 'Structure must have at least one member'}, 400)
                return

            bv = self.protocol.bv

            # Check if structure exists
            existing_type = None
            for type_name, type_obj in bv.types.items():
                if str(type_name) == name:
                    existing_type = type_obj
                    break

            if not existing_type:
                self._send_response({
                    'status': 'error',
                    'message': f"Structure '{name}' does not exist"
                }, 404)
                return

            # Validate member types and build new structure
            struct_builder = StructureBuilder.create()

            for member in members:
                member_name = member.get('name')
                member_type_str = member.get('type')
                member_count = member.get('count', 1)

                if not member_name or not member_type_str:
                    self._send_response({
                        'status': 'error',
                        'message': 'Each member must have a name and type'
                    }, 400)
                    return

                # Parse the type string
                try:
                    parsed_type, _ = bv.parse_type_string(member_type_str)
                except Exception as e:
                    self._send_response({
                        'status': 'error',
                        'message': f"Member type '{member_type_str}' does not exist or is invalid: {str(e)}"
                    }, 400)
                    return

                # Handle array types
                if member_count > 1:
                    parsed_type = Type.array(parsed_type, member_count)

                struct_builder.append(parsed_type, member_name)

            # Update the structure type (define_user_type will replace existing)
            bv.define_user_type(name, struct_builder.immutable_copy())

            # Retrieve the updated structure to return its info
            # Use types dictionary to get the actual type object
            updated_type = None
            for type_name, type_obj in bv.types.items():
                if str(type_name) == name:
                    updated_type = type_obj
                    break

            if updated_type:
                result_members = []
                try:
                    # Check if it's a structure type and get members
                    if hasattr(updated_type, 'type_class') and updated_type.type_class == TypeClass.StructureTypeClass:
                        struct = updated_type.structure
                        if struct and hasattr(struct, 'members'):
                            for m in struct.members:
                                result_members.append({
                                    'name': m.name,
                                    'type': str(m.type),
                                    'offset': m.offset
                                })
                except Exception as member_err:
                    logger.log_warn(f"Could not get structure members: {member_err}")

                self._send_response({
                    'status': 'success',
                    'message': f"Structure '{name}' updated successfully",
                    'structure': {
                        'name': name,
                        'size': updated_type.width if hasattr(updated_type, 'width') else 0,
                        'members': result_members
                    }
                })
            else:
                self._send_response({
                    'status': 'success',
                    'message': f"Structure '{name}' updated successfully"
                })

        except Exception as e:
            logger.log_error(f"Error updating structure: {e}")
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

    def _handle_set_variable_type(self, data):
        """Handle requests to set a variable's type annotation
        
        Endpoint: PUT /functions/{name}/variables/{var}/type
        Expected JSON body:
        {
            "type": "uint32_t"  # C-style type string
        }
        """
        try:
            if not data or 'type' not in data:
                self._send_response({'status': 'error', 'message': 'Type is required'}, 400)
                return
            
            type_name = data['type']
            
            # Parse path: /functions/{func_name}/variables/{var_name}/type
            path_parts = self.path.split('/')
            func_name = path_parts[2]
            var_name = path_parts[4]
            
            func = self._get_function_by_name(func_name)
            if not func:
                self._send_response({'status': 'error', 'message': f"Function '{func_name}' not found"}, 404)
                return
            
            bv = self.protocol.bv
            
            # Parse and validate the type string
            try:
                parsed_type, _ = bv.parse_type_string(type_name)
            except Exception as e:
                self._send_response({
                    'status': 'error',
                    'message': f"Type '{type_name}' not found or is invalid: {str(e)}"
                }, 400)
                return
            
            # Find the variable in the function
            target_var = None
            for var in func.vars:
                if var.name == var_name:
                    target_var = var
                    break
            
            if not target_var:
                self._send_response({
                    'status': 'error',
                    'message': f"Variable '{var_name}' not found in function '{func_name}'"
                }, 404)
                return
            
            old_type = str(target_var.type)
            
            # Set the variable type using create_user_var
            func.create_user_var(target_var, parsed_type, target_var.name)
            
            self._send_response({
                'status': 'success',
                'message': f"Variable '{var_name}' type updated from '{old_type}' to '{type_name}'",
                'variable': {
                    'name': var_name,
                    'old_type': old_type,
                    'new_type': type_name,
                    'function': func_name
                }
            })
            
        except Exception as e:
            logger.log_error(f"Error setting variable type: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_set_function_signature(self, data):
        """Handle requests to update a function's signature/prototype
        
        Endpoint: PUT /functions/{name}/signature
        Expected JSON body:
        {
            "signature": "int foo(char* arg1, int arg2)"  # C-style function signature
        }
        """
        try:
            if not data or 'signature' not in data:
                self._send_response({'status': 'error', 'message': 'Signature is required'}, 400)
                return
            
            signature = data['signature']
            
            # Parse path: /functions/{func_name}/signature
            path_parts = self.path.split('/')
            func_name = path_parts[2]
            
            func = self._get_function_by_name(func_name)
            if not func:
                self._send_response({'status': 'error', 'message': f"Function '{func_name}' not found"}, 404)
                return
            
            bv = self.protocol.bv
            old_signature = str(func.type)
            
            # Parse the C-style signature using Binary Ninja's type parser
            try:
                parsed_type, _ = bv.parse_type_string(signature)
            except Exception as e:
                self._send_response({
                    'status': 'error',
                    'message': f"Failed to parse signature '{signature}': {str(e)}"
                }, 400)
                return
            
            # Verify the parsed type is a function type
            if not hasattr(parsed_type, 'parameters'):
                self._send_response({
                    'status': 'error',
                    'message': f"Signature '{signature}' does not represent a function type"
                }, 400)
                return
            
            # Set the function's type to the parsed signature
            func.type = parsed_type
            
            self._send_response({
                'status': 'success',
                'message': f"Function '{func_name}' signature updated",
                'function': {
                    'name': func_name,
                    'old_signature': old_signature,
                    'new_signature': str(func.type)
                }
            })
            
        except Exception as e:
            logger.log_error(f"Error setting function signature: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _get_callees(self, func: binaryninja.function.Function, depth: int, visited: set) -> List[Dict[str, Any]]:
        """Get functions called by func, up to depth levels"""
        if depth == 0 or func.start in visited:
            return []
        visited.add(func.start)
        callees = []
        for site in func.call_sites:
            # Get the target address from the call site
            target_addr = None
            # Try to get the target from MLIL if available
            if hasattr(site, 'mlil') and site.mlil:
                mlil = site.mlil
                if hasattr(mlil, 'dest') and hasattr(mlil.dest, 'constant'):
                    target_addr = mlil.dest.constant

            # Fallback: try to get function at the call site address
            if target_addr is None:
                # Get the callee from the call site's referenced address
                for ref in self.protocol.bv.get_callees(site.address):
                    target_addr = ref
                    break

            if target_addr is not None:
                target = self.protocol.bv.get_function_at(target_addr)
                if target and target.start not in visited:
                    callees.append({
                        'name': target.name,
                        'address': target.start,
                        'callees': self._get_callees(target, depth - 1, visited.copy())
                    })
        return callees

    def _get_callers(self, func: binaryninja.function.Function, depth: int, visited: set) -> List[Dict[str, Any]]:
        """Get functions that call func, up to depth levels"""
        if depth == 0 or func.start in visited:
            return []
        visited.add(func.start)
        callers = []
        for ref in self.protocol.bv.get_code_refs(func.start):
            caller_funcs = self.protocol.bv.get_functions_containing(ref.address)
            if caller_funcs:
                caller = caller_funcs[0]
                if caller.start not in visited:
                    callers.append({
                        'name': caller.name,
                        'address': caller.start,
                        'callers': self._get_callers(caller, depth - 1, visited.copy())
                    })
        return callers

    def _handle_get_call_graph(self):
        """Handle requests for call graph of a function"""
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)

            # Extract function name from path: /functions/{name}/callgraph
            path_parts = parsed_path.path.split('/')
            func_name = unquote(path_parts[2]) if len(path_parts) > 2 else None

            if not func_name:
                self._send_response({'status': 'error', 'message': 'Function name required'}, 400)
                return

            # Get depth parameter (default 1, max 10)
            depth = min(int(query_params.get('depth', ['1'])[0]), 10)

            # Find the function
            func = self._get_function_by_name(func_name)
            if not func:
                self._send_response({'status': 'error', 'message': f"Function '{func_name}' not found"}, 404)
                return

            # Build call graph
            call_graph = {
                'name': func.name,
                'address': func.start,
                'callers': self._get_callers(func, depth, set()),
                'callees': self._get_callees(func, depth, set())
            }

            self._send_response({
                'status': 'success',
                'call_graph': call_graph
            })

        except Exception as e:
            logger.log_error(f"Error getting call graph: {e}")
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

    def _handle_create_tag(self, data):
        """Handle requests to create a tag at an address

        Expected JSON body:
        {
            "address": 0x401000,
            "tag_type": "review",
            "data": "needs review"  # optional
        }
        """
        try:
            address = data.get('address')
            tag_type_name = data.get('tag_type')
            tag_data = data.get('data', '')

            if address is None:
                self._send_response({'status': 'error', 'message': 'Address is required'}, 400)
                return

            if not tag_type_name:
                self._send_response({'status': 'error', 'message': 'Tag type is required'}, 400)
                return

            # Convert address if string
            if isinstance(address, str):
                address = int(address, 16) if address.startswith('0x') else int(address)

            bv = self.protocol.bv

            # Check if address is valid/mapped
            if not bv.is_valid_offset(address):
                self._send_response({
                    'status': 'error',
                    'message': f'Cannot create tag at unmapped address 0x{address:x}'
                }, 400)
                return

            # Ensure tag type exists (create if not)
            if not bv.get_tag_type(tag_type_name):
                bv.create_tag_type(tag_type_name, "⭐")

            # Find function containing this address
            funcs = bv.get_functions_containing(address)
            if funcs:
                # Create address tag within function context
                # API: func.add_tag("TagType", "data", address)
                func = funcs[0]
                func.add_tag(tag_type_name, tag_data, address)
                self._send_response({
                    'status': 'success',
                    'message': f"Tag created at 0x{address:x}",
                    'tag': {
                        'address': address,
                        'type': tag_type_name,
                        'data': tag_data,
                        'function': func.name
                    }
                })
            else:
                # Create data tag at address (not in a function)
                # API: bv.add_tag(address, "TagType", "data")
                bv.add_tag(address, tag_type_name, tag_data)
                self._send_response({
                    'status': 'success',
                    'message': f"Tag created at 0x{address:x}",
                    'tag': {
                        'address': address,
                        'type': tag_type_name,
                        'data': tag_data,
                        'function': None
                    }
                })

        except Exception as e:
            logger.log_error(f"Error creating tag: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_tags(self):
        """Handle requests to list all tags

        Query parameters:
        - type: Optional filter by tag type name
        """
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            tag_type_filter = query_params.get('type', [None])[0]

            bv = self.protocol.bv
            tags = []

            # Iterate through all tag types and get tags
            for tag_type in bv.tag_types.values():
                tag_type_name = tag_type.name
                
                # Apply filter if specified
                if tag_type_filter and tag_type_name != tag_type_filter:
                    continue
                
                # Get all tags of this type using bv.get_tags_at or iterate functions
                # Try to get tags from each function
                for func in bv.functions:
                    try:
                        # Get tags at each address in the function
                        func_tags = bv.get_tags_in_range(func.start, func.address_ranges[0].end - func.start) if func.address_ranges else []
                        for addr, tag_list in func_tags if isinstance(func_tags, dict) else []:
                            for tag in (tag_list if isinstance(tag_list, list) else [tag_list]):
                                if tag.type.name == tag_type_name:
                                    tags.append({
                                        'address': addr,
                                        'type': tag_type_name,
                                        'data': tag.data,
                                        'function': func.name
                                    })
                    except Exception:
                        pass

            # Deduplicate tags by address+type
            seen = set()
            unique_tags = []
            for tag in tags:
                key = (tag['address'], tag['type'])
                if key not in seen:
                    seen.add(key)
                    unique_tags.append(tag)

            self._send_response({
                'status': 'success',
                'tags': unique_tags,
                'count': len(unique_tags)
            })

        except Exception as e:
            logger.log_error(f"Error getting tags: {e}")
            logger.log_error("Stack trace: %s" % traceback.format_exc())
            self._send_response({'status': 'error', 'message': str(e)}, 500)

    def _handle_get_analysis_progress(self):
        """Handle requests to get analysis progress

        Returns the current analysis state, completion status, and progress percentage.
        """
        try:
            bv = self.protocol.bv

            # Try different ways to get analysis state
            state_name = 'Unknown'
            is_complete = False
            progress = 0.5
            
            # Method 1: Try analysis_info.state
            if hasattr(bv, 'analysis_info') and bv.analysis_info:
                try:
                    state = bv.analysis_info.state
                    state_name = state.name if hasattr(state, 'name') else str(state)
                except:
                    pass
            
            # Method 2: Try analysis_progress directly on bv
            if hasattr(bv, 'analysis_progress'):
                try:
                    ap = bv.analysis_progress
                    if hasattr(ap, 'state'):
                        state_name = ap.state.name if hasattr(ap.state, 'name') else str(ap.state)
                except:
                    pass
            
            # Determine if analysis is complete
            is_complete = 'Idle' in state_name or state_name == 'IdleState'

            # Estimate progress based on state
            state_progress_map = {
                'InitialState': 0.0,
                'HoldState': 0.0,
                'DisassembleState': 0.25,
                'AnalyzeState': 0.5,
                'ExtendedAnalyzeState': 0.75,
                'IdleState': 1.0
            }
            progress = state_progress_map.get(state_name, 1.0 if is_complete else 0.5)

            # Build description based on state
            state_descriptions = {
                'InitialState': 'Initial analysis starting',
                'HoldState': 'Analysis on hold',
                'IdleState': 'Analysis complete',
                'DisassembleState': 'Disassembling binary',
                'AnalyzeState': 'Analyzing functions',
                'ExtendedAnalyzeState': 'Performing extended analysis'
            }
            description = state_descriptions.get(state_name, f'Analysis in progress ({state_name})')

            self._send_response({
                'status': 'success',
                'state': state_name,
                'is_complete': is_complete,
                'progress': round(progress, 4),
                'description': description
            })

        except Exception as e:
            logger.log_error(f"Error getting analysis progress: {e}")
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
    
    def __init__(self, bv: BinaryView, config: LatticeConfig):
        """
        Initialize the model context protocol.
        
        Args:
            bv: BinaryView object representing the currently analyzed binary
            port: Port number for communication
            host: Host address for the server
            use_ssl: Whether to use SSL/TLS encryption
        """
        self._bv = bv

        config.get_host()
        config.get_port()
        config.get_use_ssl()

        self.port = config.port
        self.host = config.ip_address
        self.use_ssl = config.use_ssl

        self.auth_manager = AuthManager(config)
        self.server = None

    @property
    def bv(self):
        """
        Dynamically retrieves the current BinaryView every time "self.bv" is accessed.
        Uses the original view type (e.g. "PE", "ELF") to fetch the live view from the
        file metadata, ensuring operations like bv.read() reflect UI state changes such
        as a manual rebase or re-analysis without needing to restart Lattice MCP.
        """
        view_type = self._bv.view_type
        updated = self._bv.file.get_view_of_type(view_type)
        return updated if updated is not None else self._bv

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
    config = LatticeConfig()

    protocol = BinjaLattice(view, config)
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
