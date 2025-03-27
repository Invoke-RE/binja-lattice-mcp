# BinjaLattice

BinjaLattice is a secure communication protocol for Binary Ninja that enables interaction with external Model Context Protocol (MCP) servers and tools. It provides a structured way to exchange binary analysis data between Binary Ninja and external systems.

## Features

- **Secure Authentication**: Token-based authentication system
- **Encrypted Communication**: Optional SSL/TLS encryption
- **Binary Analysis Context**: Export function context, basic blocks, variables, etc.
- **Binary Modification**: Update function names, add comments, rename variables
- **Token Management**: Automatic expiration and renewal of authentication tokens

## Installation

1. Copy `agent.py` to your Binary Ninja plugins directory:
   - Linux: `~/.binaryninja/plugins/`
   - macOS: `~/Library/Application Support/Binary Ninja/plugins/`
   - Windows: `%APPDATA%\Binary Ninja\plugins\`

2. Required Python dependencies:
   - `pyOpenSSL` (for SSL certificate generation)
   - Install with: `pip install pyOpenSSL`

## Usage

### Starting the Server in Binary Ninja

1. Open Binary Ninja and load a binary file
2. Go to `Tools > Start Lattice Protocol Server`
3. The server will start and display the API key in the log console
4. Note the API key shown in the log - you'll need this to authenticate clients

### Connecting Clients

#### Sample Python Client Code

```python
from lattice_client import LatticeClient

# Connect to the BinjaLattice server
client = LatticeClient(host="localhost", port=9000, use_ssl=True)
if client.connect():
    # Authenticate with the API key shown in Binary Ninja's log
    if client.authenticate("user", "YOUR_API_KEY_HERE"):
        # Get binary information
        binary_info = client.get_binary_info()
        print(f"Analyzing binary: {binary_info['binary_info']['filename']}")
        
        # Get function at address 0x1000
        function = client.get_function_context(0x1000)
        if function['status'] == 'success':
            print(f"Function name: {function['function']['name']}")
            
            # Update function name
            client.update_function_name(0x1000, "new_function_name")
            
            # Add a comment
            client.add_comment(0x1000, "This function was renamed by MCP server")
    
    # Close connection when done
    client.close()
```

### Authentication Methods

#### Username/Password Authentication

The first time a client connects, it must authenticate with the API key:

```python
client.authenticate("username", "API_KEY")
```

#### Token-based Authentication

After initial authentication, the client receives a token that can be used for future connections:

```python
# Store this token securely after the first authentication
token = client.token

# Later, reconnect with the token
client = LatticeClient()
client.connect()
client.authenticate_with_token(token)
```

## Security Notes

- The API key is generated randomly on server start and shown in the Binary Ninja log
- Tokens expire after 1 hour by default
- SSL/TLS uses a self-signed certificate for development; replace with proper certificates for production use
- Clients must include their authentication token with every request

## Protocol Specification

### Authentication

```json
// Request
{
  "type": "authenticate",
  "username": "user",
  "password": "API_KEY"
}

// Response
{
  "status": "success",
  "message": "Authentication successful",
  "token": "a1b2c3d4e5f6g7h8i9j0"
}
```

### Getting Binary Information

```json
// Request
{
  "type": "get_binary_info",
  "token": "a1b2c3d4e5f6g7h8i9j0"
}

// Response
{
  "status": "success",
  "binary_info": {
    "filename": "example.bin",
    "file_size": 12345,
    "start": 4194304,
    "end": 4456448,
    "entry_point": 4194826,
    "arch": "x86_64",
    "platform": "linux-x86_64",
    "functions_count": 42,
    "symbols_count": 150
  }
}
```

### Getting Function Context

```json
// Request
{
  "type": "get_function_context",
  "address": 4194826,
  "token": "a1b2c3d4e5f6g7h8i9j0"
}

// Response
{
  "status": "success",
  "function": {
    "name": "main",
    "start": 4194826,
    "end": 4194901,
    "disassembly": [...],
    "llil": [...],
    "mlil": [...],
    "hlil": [...],
    "variables": [...]
  }
}
```

### Getting Function Disassembly

```json
// Request
{
  "type": "get_function_disassembly",
  "address": 4194826,
  "token": "a1b2c3d4e5f6g7h8i9j0"
}

// Response
{
  "status": "success",
  "disassembly": [
    {
      "address": 4194826,
      "text": "push rbp",
      "bytes": ["0x55"],
      "length": 1
    },
    ...
  ]
}
```

### Getting Function Pseudocode

```json
// Request
{
  "type": "get_function_pseudocode",
  "address": 4194826,
  "token": "a1b2c3d4e5f6g7h8i9j0"
}

// Response
{
  "status": "success",
  "pseudocode": [
    "0x4194826: void main() {",
    "0x4194827:     int32_t var_4 = 0",
    ...
  ]
}
```

### Getting Function Variables

```json
// Request
{
  "type": "get_function_variables",
  "address": 4194826,
  "token": "a1b2c3d4e5f6g7h8i9j0"
}

// Response
{
  "status": "success",
  "variables": {
    "parameters": [
      {
        "name": "argc",
        "type": "int32_t",
        "location": "rdi"
      }
    ],
    "local_variables": [
      {
        "name": "var_4",
        "type": "int32_t",
        "location": "rbp-0x4",
        "id": 1
      }
    ]
  }
}
```

## Command Line Interface

The client includes a command-line interface with the following options:

### Interactive Mode
```bash
python lattice_client.py --interactive
```

### Command Line Options

- `--host`: Server host (default: localhost)
- `--port`: Server port (default: 9000)
- `--ssl`: Use SSL/TLS encryption
- `--interactive`, `-i`: Run in interactive mode

### Authentication Options
- `--username`: Username for authentication
- `--password`: Password/API key for authentication
- `--token`: Authentication token

### Available Commands
- `--get-binary-info`: Get binary information
- `--get-function-context`: Get function context at address (hex or decimal)
- `--get-basic-block-context`: Get basic block context at address (hex or decimal)
- `--update-function-name`: Update function name: `<address> <new_name>`
- `--update-variable-name`: Update variable name: `<function_address> <var_id> <new_name>`
- `--add-comment`: Add comment: `<address> <comment>`
- `--get-function-disassembly`: Get function disassembly at address (hex or decimal)
- `--get-function-pseudocode`: Get function pseudocode at address (hex or decimal)
- `--get-function-variables`: Get function variables at address (hex or decimal)

### Example Usage

```bash
# Get function disassembly
python lattice_client.py --get-function-disassembly 0x1000

# Get function pseudocode
python lattice_client.py --get-function-pseudocode 0x1000

# Get function variables
python lattice_client.py --get-function-variables 0x1000

# Interactive mode with SSL
python lattice_client.py --interactive --ssl --username user --password YOUR_API_KEY
```

## Development

- To modify the protocol, edit the handler functions in `agent.py`
- To add new API endpoints, add new handlers to the `_process_request` method
- To modify authentication behavior, edit the `AuthManager` class

## License

[MIT License](LICENSE) 