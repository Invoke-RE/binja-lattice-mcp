import os
import sys
import time
import requests
import pytest
import binaryninja

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from plugin.lattice_server_plugin import BinjaLattice

@pytest.fixture(scope="module")
def bv():
    """Create a headless BinaryView from our test binary"""
    bv = binaryninja.load("tests/data/test_binary")
    return bv

@pytest.fixture(scope="module")
def lattice_server(bv):
    """Start the Lattice server and yield its configuration"""
    protocol = BinjaLattice(bv, host="127.0.0.1", port=0)
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
    return j["token"]  # Return token for other tests

def test_binary_info_endpoint(lattice_server):
    """Test the binary info endpoint"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    token = test_auth_succeeds_with_valid_credentials(lattice_server)

    r = requests.get(
        f"{base}/binary/info",
        headers={"Authorization": f"Bearer {token}"}
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

def test_function_operations(lattice_server):
    """Test function-related endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    token = test_auth_succeeds_with_valid_credentials(lattice_server)
    headers = {"Authorization": f"Bearer {token}"}

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

def test_comment_operations(lattice_server):
    """Test comment-related endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    token = test_auth_succeeds_with_valid_credentials(lattice_server)
    headers = {"Authorization": f"Bearer {token}"}

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

def test_variable_operations(lattice_server):
    """Test variable-related endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    token = test_auth_succeeds_with_valid_credentials(lattice_server)
    headers = {"Authorization": f"Bearer {token}"}

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

def test_cross_references(lattice_server):
    """Test cross-reference endpoints"""
    base = lattice_server["base"]
    bv = lattice_server["bv"]
    token = test_auth_succeeds_with_valid_credentials(lattice_server)
    headers = {"Authorization": f"Bearer {token}"}

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