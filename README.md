# BinjaLattice

BinjaLattice is a secure communication protocol for Binary Ninja that enables interaction with external Model Context Protocol (MCP) servers and tools. It provides a structured way to acquire information from Binary Ninja and the ability to modify an active Binary Ninja database over HTTP with a REST API.

## Features

- **Secure Authentication**: Token-based authentication system
- **Encrypted Communication**: Optional SSL/TLS encryption
- **Binary Analysis Context**: Export pseudocode, disassembly, variable names, binary information etc.
- **Binary Modification**: Update function names, add comments, rename variables
- **Token Management**: Automatic expiration and renewal of authentication tokens

## Installation

1. Copy `agent.py` to your Binary Ninja plugins directory:
   - Linux: `~/.binaryninja/plugins/`
   - macOS: `~/Library/Application Support/Binary Ninja/plugins/`
   - Windows: `%APPDATA%\Binary Ninja\plugins\`

2. Create a virtual environment `pip -m venv venv-test` (or your preferred dependency manager)

3. Activate your virtual environment and install required Python dependencies:
   - Install with: `pip install -r requirements.txt` (or your preferred method)

## Usage

### Starting the Server in Binary Ninja

1. Open Binary Ninja and load a binary file
2. Go to `Plugins > Start Lattice Protocol Server`
3. The server will start and display the API key in the log console
4. Set the API key as the `BNJLAT` environment variable in your MCP configuration

Example MCP configuration (`mcp.json`) from Cursor:
```json
{
    "mcpServers": {
      "binja-lattice-mcp": {
        "command": "/path/to/venv/bin/python",
        "args": ["/path/to/mcp_server.py"],
        "env": {
            "BNJLAT": "your_api_key_here"
        }
      }
    }
}
```

### Available MCP Tools

The following tools are available through the MCP server:

- `get_all_function_names`: Get a list of all function names in the binary
- `get_binary_info`: Get information about the binary being analyzed
- `update_function_name`: Update the name of a function
- `add_comment_to_address`: Add a comment to a specific address
- `add_comment_to_function`: Add a comment to a function
- `get_function_disassembly`: Get disassembly for a function
- `get_function_pseudocode`: Get pseudocode for a function
- `get_function_variables`: Get variables and parameters for a function
- `get_cross_references_to_function`: Get cross references to a function

### Client Library Usage

The `Lattice` client library provides a Python interface for interacting with the BinjaLattice server:

```python
from lib.lattice import Lattice

# Initialize client
client = Lattice(host='localhost', port=9000, use_ssl=False)

# Authenticate with API key
client.authenticate("username", "API_KEY")

# Example: Get binary information
binary_info = client.get_binary_info()

# Example: Update function name
client.update_function_name("old_name", "new_name")

# Example: Add comment to function
client.add_comment_to_function("function_name", "This function handles authentication")
```

### Command Line Interface

The project includes `lattice_client.py`, which provides an interactive command-line interface for testing and debugging the BinjaLattice server:

```bash
python lattice_client.py --host localhost --port 9000 [--ssl] --username user --password YOUR_API_KEY
```

#### Command Line Options

- `--host`: Server host (default: localhost)
- `--port`: Server port (default: 9000)
- `--ssl`: Enable SSL/TLS encryption
- `--interactive`, `-i`: Run in interactive mode
- `--username`: Username for authentication
- `--password`: Password/API key for authentication
- `--token`: Authentication token (if you have one from previous authentication)

#### Interactive Mode

The interactive mode provides a menu-driven interface with the following options:

1. Get Binary Information
2. Get Function Context by Address
3. Get Function Context by Name
4. Update Function Name
5. Update Variable Name
6. Add Comment to Function
7. Add Comment to Address
8. Reconnect to Server
9. Get All Function Names
10. Get Function Disassembly
11. Get Function Pseudocode
12. Get Function Variables
13. Get Cross References to Function
14. Exit

Example usage with interactive mode:

```bash
python lattice_client.py -i --ssl --username user --password YOUR_API_KEY
```

#### Non-Interactive Commands

You can also use the client to execute single commands:

```bash
# Get binary information
python lattice_client.py --username user --password YOUR_API_KEY --get-binary-info

# Get function disassembly
python lattice_client.py --username user --password YOUR_API_KEY --get-function-disassembly "main"

# Add comment to a function
python lattice_client.py --username user --password YOUR_API_KEY --add-comment-to-function "main" "Entry point of the program"
```

### Security Notes

- The API key is generated randomly on server start and shown in the Binary Ninja log
- Tokens expire after 8 hours by default
- SSL/TLS requires a certificate and key be provided by the user (disabled by default)
- All requests require authentication via API key or token
- The server runs locally by default on port 9000

## Development

- The main server implementation is in `plugin/agent.py`
- MCP server implementation is in `mcp_server.py`
- Client library is in `lib/lattice.py`

### Adding New Features

To add new functionality:

1. Add new endpoint handlers in `LatticeRequestHandler` class in `agent.py`
2. Add corresponding client methods in `Lattice` class in `lib/lattice.py`
3. Add new MCP tools in `mcp_server.py`

## License

[MIT License](LICENSE) 
