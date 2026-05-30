import os
import sys
import time
import requests
import pytest
import binaryninja
from binaryninja import HighLevelILConstPtr

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from plugin.lattice_server_plugin import AuthManager, BinjaLattice, LatticeConfig

@pytest.fixture(scope="module")
def bv():
    """Create a headless BinaryView from our test binary"""
    bv = binaryninja.load("tests/data/test_binary")
    return bv

@pytest.fixture(scope="module")
def lattice_server(bv):
    """Start the Lattice server and yield its configuration"""
    # Build a LatticeConfig and override the value-loading hooks so the server
    # binds to localhost on an ephemeral port regardless of any on-disk config.
    config = LatticeConfig()
    config.ip_address = "127.0.0.1"
    config.port = 0
    config.use_ssl = False
    config.get_host = lambda *a, **kw: None
    config.get_port = lambda *a, **kw: None
    config.get_use_ssl = lambda *a, **kw: None

    protocol = BinjaLattice(bv, config)
    protocol.start_server()
    # Give it a moment to bind
    time.sleep(0.1)

    host, port = protocol.server.server_address
    base = f"http://{host}:{port}"
    api_key = protocol.auth_manager.api_key

    yield {
        "protocol": protocol,
        "base": base,
        "api_key": api_key,
        "bv": bv
    }

    # Teardown
    protocol.stop_server()
    # TODO figure out if this is actually possible
    # bv.close()

@pytest.fixture
def auth_token(lattice_server):
    """Authenticate against the test server and return a bearer token."""
    r = requests.post(
        f"{lattice_server['base']}/auth",
        json={"username": "test_user", "password": lattice_server["api_key"]}
    )
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "success"
    assert "token" in j
    return j["token"]

def test_auth_fails_without_credentials(lattice_server):
    """Test that authentication fails without proper credentials"""
    r = requests.post(f"{lattice_server['base']}/auth", json={})
    assert r.status_code == 401
    assert r.json()["status"] == "error"

def test_auth_succeeds_with_valid_credentials(lattice_server):
    """Test that authentication succeeds with valid API key"""
    base = lattice_server["base"]
    api_key = lattice_server["api_key"]

    r = requests.post(
        f"{base}/auth",
        json={"username": "test_user", "password": api_key}
    )
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "success"
    assert "token" in j

def test_auth_rejects_bad_api_key(lattice_server):
    """Test that authentication rejects incorrect API keys."""
    r = requests.post(
        f"{lattice_server['base']}/auth",
        json={"username": "test_user", "password": "not-the-api-key"}
    )
    assert r.status_code == 401
    assert r.json()["status"] == "error"

def test_auth_accepts_existing_valid_token(lattice_server, auth_token):
    """Test that /auth can validate and return an existing bearer token."""
    r = requests.post(
        f"{lattice_server['base']}/auth",
        json={"token": auth_token}
    )
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "success"
    assert j["token"] == auth_token

def test_binary_info_endpoint(lattice_server, auth_token):
    """Test the binary info endpoint"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]

    r = requests.get(
        f"{base}/binary/info",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "success"
    info = j["binary_info"]
    
    # Assert against actual BinaryView properties
    assert info["filename"].endswith("test_binary")
    assert info["arch"] == bv.arch.name
    assert info["platform"] == bv.platform.name
    assert info["entry_point"] == bv.entry_point
    assert info["start"] == bv.start
    assert info["end"] == bv.end
    assert info["functions_count"] == len(bv.functions)
    assert info["symbols_count"] == len(bv.symbols)
    assert isinstance(info["segments"], list)
    assert isinstance(info["sections"], list)

def test_function_operations(lattice_server, auth_token):
    """Test function-related endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Test getting all functions
    r = requests.get(f"{base}/functions", headers=headers)
    assert r.status_code == 200
    functions = r.json()["function_names"]
    assert len(functions) > 0
    
    # Test getting function context for main function
    main_func = next(f for f in functions if f["name"] == "_main")
    r = requests.get(
        f"{base}/functions/{main_func['address']}",
        headers=headers
    )
    assert r.status_code == 200
    func_info = r.json()["function"]
    
    # Assert function properties match BinaryView
    actual_func = bv.get_function_at(main_func["address"])
    assert func_info["name"] == actual_func.name
    assert func_info["start"] == actual_func.start
    assert func_info["end"] == actual_func.address_ranges[0].end

def test_function_context_by_name_endpoint(lattice_server, auth_token):
    """Test getting function context by function name."""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    main_func = next(f for f in bv.functions if f.name == "_main")

    r = requests.get(f"{base}/functions/name/{main_func.name}", headers=headers)
    assert r.status_code == 200
    func_info = r.json()["function"]
    assert func_info["name"] == main_func.name
    assert func_info["start"] == main_func.start
    assert "pseudo_c" in func_info
    assert "disassembly" in func_info

def test_function_text_endpoints(lattice_server, auth_token):
    """Test disassembly and pseudocode endpoints for a named function."""
    base = lattice_server["base"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    r = requests.get(f"{base}/functions/_main/disassembly", headers=headers)
    assert r.status_code == 200
    disassembly = r.json()["disassembly"]
    assert len(disassembly) > 0
    assert all({"address", "text"} <= set(line) for line in disassembly)

    r = requests.get(f"{base}/functions/_main/pseudocode", headers=headers)
    assert r.status_code == 200
    pseudocode = r.json()["pseudocode"]
    assert len(pseudocode) > 0
    assert any("_print_message" in line["text"] for line in pseudocode)

def test_call_graph_endpoint(lattice_server, auth_token):
    """Test that the call graph reports direct callees."""
    base = lattice_server["base"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    r = requests.get(f"{base}/functions/_main/callgraph?depth=1", headers=headers)
    assert r.status_code == 200
    call_graph = r.json()["call_graph"]
    assert call_graph["name"] == "_main"
    callee_names = {callee["name"] for callee in call_graph["callees"]}
    assert {"_add", "_print_message"} <= callee_names

def test_comment_operations(lattice_server, auth_token):
    """Test comment-related endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Test adding a comment to main function
    main_func = next(f for f in bv.functions if f.name == "_main")
    test_comment = "Test comment for main function"
    
    r = requests.post(
        f"{base}/functions/{main_func.name}/comments",
        headers=headers,
        json={"comment": test_comment}
    )
    assert r.status_code == 200
    
    # Verify comment was added
    assert bv.get_comment_at(main_func.start) == test_comment

def test_address_comment_endpoint(lattice_server, auth_token):
    """Test adding a comment directly to an address."""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    add_func = next(f for f in bv.functions if f.name == "_add")
    test_comment = "Test address comment for add"

    r = requests.post(
        f"{base}/comments/{add_func.start:#x}",
        headers=headers,
        json={"comment": test_comment}
    )
    assert r.status_code == 200
    assert bv.get_comment_at(add_func.start) == test_comment

def test_variable_operations(lattice_server, auth_token):
    """Test variable-related endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Test getting variables for main function
    main_func = next(f for f in bv.functions if f.name == "_main")
    r = requests.get(
        f"{base}/functions/{main_func.name}/variables",
        headers=headers
    )
    assert r.status_code == 200
    vars_info = r.json()["variables"]
    
    # Assert variables match BinaryView
    assert len(vars_info["parameters"]) == len(main_func.parameter_vars)
    assert len(vars_info["local_variables"]) == len(main_func.vars)

    # Compute the expected global-variable set by replicating the server's
    # HLIL const-pointer traversal. This keeps the assertion accurate even if
    # Binary Ninja's analysis surfaces a different number of pointer refs.
    expected_global_addrs = set()
    for bb in main_func.hlil:
        for instr in bb:
            for ptr in instr.traverse(
                lambda o: o if isinstance(o, HighLevelILConstPtr) else None
            ):
                if ptr.constant in bv.data_vars:
                    expected_global_addrs.add(ptr.constant)

    actual_global_addrs = {g["location"] for g in vars_info["global_variables"]}
    assert actual_global_addrs == expected_global_addrs
    assert len(vars_info["global_variables"]) == len(expected_global_addrs)

def test_variable_name_update(lattice_server, auth_token):
    """Test variable name update endpoint"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Test getting variables for main function
    main_func = next(f for f in bv.functions if f.name == "_main")
    r = requests.get(
        f"{base}/functions/{main_func.name}/variables",
        headers=headers
    )
    assert r.status_code == 200
    vars_info = r.json()["variables"]
    var_name = vars_info["local_variables"][0]["name"]
    # Test updating variable name
    r = requests.put(
        f"{base}/variables/{main_func.name}/{var_name}/name",
        headers=headers,
        json={"name": "new_var_name"}
    )
    assert r.status_code == 200
    r = requests.get(
        f"{base}/functions/{main_func.name}/variables",
        headers=headers
    )
    assert r.status_code == 200
    vars_info = r.json()["variables"]
    print(vars_info)
    # This assumes that the variables maintain order after being renamed
    assert vars_info["local_variables"][0]["name"] == "new_var_name"

def test_get_global_variable_data(lattice_server, auth_token):
    """Test getting data for a global variable"""
    base = lattice_server["base"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # This is a global variable in the main function
    # as per our returned convention because it is unnamed
    r = requests.get(
        f"{base}/global_variable_data/_main/data_100003f90",
        headers=headers
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert "Hello, World!" in data["message"]

def test_cross_references(lattice_server, auth_token):
    """Test cross-reference endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    # Test getting cross references to print_message function
    print_func = next(f for f in bv.functions if f.name == "_print_message")
    r = requests.get(
        f"{base}/cross-references/{print_func.name}",
        headers=headers
    )
    assert r.status_code == 200
    refs = r.json()["cross_references"]
    
    # Should have at least one reference from main
    assert len(refs) > 0
    assert any(ref["function"] == "_main" for ref in refs)

def test_strings_imports_exports_and_types_endpoints(lattice_server, auth_token):
    """Test binary-wide metadata endpoints that do not mutate the BinaryView."""
    base = lattice_server["base"]
    headers = {"Authorization": f"Bearer {auth_token}"}

    r = requests.get(f"{base}/strings?min_length=5&filter=hello", headers=headers)
    assert r.status_code == 200
    strings = r.json()["strings"]
    assert any(s["value"] == "Hello, World!" and s["length"] >= 5 for s in strings)

    r = requests.get(f"{base}/imports", headers=headers)
    assert r.status_code == 200
    imports = r.json()["imports"]
    assert any(i["name"] == "_printf" for i in imports)

    r = requests.get(f"{base}/exports", headers=headers)
    assert r.status_code == 200
    exports = r.json()["exports"]
    assert {"_add", "_print_message", "_main"} <= {e["name"] for e in exports}

    r = requests.get(f"{base}/types?filter=mach", headers=headers)
    assert r.status_code == 200
    assert all("mach" in t["name"].lower() for t in r.json()["types"])

def test_data_and_byte_search_endpoints(lattice_server, auth_token):
    """Test reading bytes at an address and searching for a byte pattern."""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    main_func = next(f for f in bv.functions if f.name == "_main")
    expected_bytes = bv.read(main_func.start, 4)

    r = requests.get(f"{base}/data/{main_func.start:#x}?length=4", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["address"] == main_func.start
    assert data["hex"] == expected_bytes.hex()
    assert data["length"] == 4

    r = requests.post(
        f"{base}/search/bytes",
        headers=headers,
        json={"pattern": expected_bytes.hex(), "max_results": 10}
    )
    assert r.status_code == 200
    search = r.json()
    assert search["status"] == "success"
    assert search["pattern"] == expected_bytes.hex()
    assert any(result["address"] == main_func.start for result in search["results"])

def test_analysis_progress_endpoint(lattice_server, auth_token):
    """Test analysis progress reports a well-formed state."""
    r = requests.get(
        f"{lattice_server['base']}/analysis/progress",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert r.status_code == 200
    progress = r.json()
    assert progress["status"] == "success"
    assert isinstance(progress["state"], str)
    assert isinstance(progress["is_complete"], bool)
    assert 0 <= progress["progress"] <= 1
    assert isinstance(progress["description"], str)

def test_protected_endpoints_require_auth(lattice_server):
    """Test that protected endpoints require authentication"""
    base = lattice_server["base"]
    endpoints = [
        "/binary/info",
        "/functions",
        "/functions/main",
        "/functions/main/variables"
    ]
    
    for endpoint in endpoints:
        r = requests.get(f"{base}{endpoint}")
        assert r.status_code == 401
        assert r.json()["status"] == "error" 

def test_protected_endpoint_rejects_invalid_token(lattice_server):
    """Test that protected routes reject invalid bearer tokens."""
    r = requests.get(
        f"{lattice_server['base']}/functions",
        headers={"Authorization": "Bearer invalid-token"}
    )
    assert r.status_code == 401
    assert r.json()["status"] == "error"

def test_auth_manager_token_lifecycle():
    """Test token validation, revocation, and expiry cleanup."""
    config = LatticeConfig()
    auth = AuthManager(config, token_expiry_seconds=60)
    client_info = {"username": "unit-test"}

    token = auth.generate_token(client_info)
    is_valid, returned_info = auth.validate_token(token)
    assert is_valid is True
    assert returned_info == client_info

    assert auth.revoke_token(token) is True
    assert auth.validate_token(token) == (False, None)
    assert auth.revoke_token(token) is False

    expired_token = auth.generate_token(client_info)
    auth.tokens[expired_token] = (time.time() - 1, client_info)
    assert auth.validate_token(expired_token) == (False, None)
    assert expired_token not in auth.tokens

def test_lattice_config_validates_host_port_ssl_and_api_key(tmp_path):
    """Test config parsing accepts valid values and falls back on invalid values."""
    valid_config = tmp_path / "valid.ini"
    valid_config.write_text(
        "[lattice]\n"
        "ip_address = 127.0.0.1\n"
        "port = 12345\n"
        "use_ssl = True\n"
        "api_key = configured-key\n"
    )

    config = LatticeConfig(str(valid_config))
    config.get_host()
    config.get_port()
    config.get_use_ssl()
    config.get_api_key()
    assert config.ip_address == "127.0.0.1"
    assert config.port == 12345
    assert config.use_ssl is True
    assert config.api_key == "configured-key"

    invalid_config = tmp_path / "invalid.ini"
    invalid_config.write_text(
        "[lattice]\n"
        "ip_address = not-an-ip\n"
        "port = 22\n"
        "use_ssl = maybe\n"
    )

    config = LatticeConfig(str(invalid_config))
    config.get_host(default="127.0.0.1")
    config.get_port(default=9000)
    config.get_use_ssl(default=False)
    config.get_api_key()
    assert config.ip_address == "127.0.0.1"
    assert config.port == 9000
    assert config.use_ssl is False
    assert config.api_key == config.new_api_key