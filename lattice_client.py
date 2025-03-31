from lib.lattice import Lattice
import argparse, sys, json

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
    print("12. Get Cross References to Address")
    print("13. Exit")
    print()

def interactive_mode(client: Lattice):
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
                addr = input("Enter address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_cross_references_to_address(address)
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
    command_group.add_argument('--get-cross-references-to-address', type=lambda x: int(x, 0), help='Get cross references to address (hex or decimal)')
    
    args = parser.parse_args()
    
    # Create client
    client = Lattice(host=args.host, port=args.port, use_ssl=args.ssl)
    
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

            elif args.get_cross_references_to_address:
                result = client.get_cross_references_to_address(args.get_cross_references_to_address)
                print(json.dumps(result, indent=2))
            else:
                print("No command specified. Use --help to see available commands.")
                
    finally:
        client.close()

if __name__ == "__main__":
    main() 
