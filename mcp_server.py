from mcp.server.fastmcp import FastMCP
from lib.lattice import Lattice
import os, json

# Initialize FastMCP server
mcp = FastMCP("binja-lattice", log_level="ERROR")

@mcp.tool()
def get_all_function_names() -> str:
    """Get all function names"""
    response = lattice_client.get_all_function_names()
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join(response['function_names'])
    return "Error: Could not retrieve function names"

@mcp.tool()
def get_binary_info() -> str:
    """Get information about the binary being analyzed"""
    response = lattice_client.get_binary_info()
    if response and 'status' in response and response['status'] == 'success':
        return json.dumps(response, indent=2)
    return "Error: Could not retrieve binary information"

@mcp.tool()
def update_function_name(address: int, new_name: str) -> str:
    """Update the name of a function at the specified address"""
    response = lattice_client.update_function_name(address, new_name)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully renamed function at {hex(address)} to {new_name}"
    return f"Error: Could not update function name at address {hex(address)}"

@mcp.tool()
def add_comment(address: int, comment: str) -> str:
    """Add a comment at the specified address"""
    response = lattice_client.add_comment(address, comment)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully added comment at {hex(address)}"
    return f"Error: Could not add comment at address {hex(address)}"

@mcp.tool()
def get_function_disassembly(address: int) -> str:
    """Get disassembly for the function at the specified address"""
    response = lattice_client.get_function_disassembly(address)
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{block['address']}: {block['text']}" for block in response['disassembly']])
    return f"Error: Could not retrieve function disassembly for address {hex(address)}"

@mcp.tool()
def get_function_pseudocode(address: int) -> str:
    """Get pseudocode for the function at the specified address"""
    response = lattice_client.get_function_pseudocode(address)
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{block['address']}: {block['text']}" for block in response['pseudocode']])
    return f"Error: Could not retrieve function pseudocode for address {hex(address)}"

@mcp.tool()
def get_function_variables(address: int) -> str:
    """Get variables for the function at the specified address"""
    response = lattice_client.get_function_variables(address)
    if response and 'status' in response and response['status'] == 'success':
        return 'Parameters: ' + '\n'.join([f"{param['name']}: {param['type']}" for param in response['variables']['parameters']]) + '\nLocal Variables: ' + '\n'.join([f"{var['name']}: {var['type']}" for var in response['variables']['local_variables']])
    return f"Error: Could not retrieve function variables for address {hex(address)}"

@mcp.tool()
def get_cross_references_to_address(address: int) -> str:
    """Get cross references to the specified address"""
    response = lattice_client.get_cross_references_to_address(address)
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{ref['address']}" for ref in response['cross_references']])
    return f"Error: Could not retrieve cross references for address {hex(address)}"

# Initialize and run the server
api_key = os.getenv("BNJLAT")
if not api_key:
    raise ValueError("BNJLAT environment variable not set")

global lattice_client
lattice_client = Lattice()
print(f"Authenticating with {api_key}")
lattice_client.authenticate("mcp-user", api_key)
mcp.run(transport='stdio')
