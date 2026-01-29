"""Example demonstrating FrappeClient integration with FrappeAuthBridge."""

import os
from frappe_auth_bridge import FrappeAuthBridge

# Initialize
FRAPPE_URL = os.getenv("FRAPPE_URL", "https://example.erpnext.com")
auth = FrappeAuthBridge(frappe_url=FRAPPE_URL)

def example_1_after_login():
    """Example 1: Using client after login."""
    print("=== Example 1: Client After Login ===\n")
    
    # Login
    session = auth.login_with_password("user@example.com", "password")
    print(f"✓ Logged in as: {session.user.email}\n")
    
    # Now you can use auth.client directly
    # The client is automatically authenticated from the login
    
    # Get a document
    user_doc = auth.client.get_doc("User", "user@example.com")
    print(f"User document: {user_doc.get('full_name')}")
    
    # List documents
    users = auth.client.get_list(
        "User",
        fields=["name", "email", "full_name"],
        filters={"enabled": 1},
        limit_page_length=10
    )
    print(f"Found {len(users)} users")
    
    # Insert a document
    new_todo = auth.client.insert({
        "doctype": "ToDo",
        "description": "Test todo from auth bridge"
    })
    print(f"Created ToDo: {new_todo.get('name')}")
    
    # Update a document
    auth.client.update({
        "doctype": "ToDo",
        "name": new_todo.get('name'),
        "status": "Closed"
    })
    print("Updated ToDo status")
    
    # Delete a document
    auth.client.delete("ToDo", new_todo.get('name'))
    print("Deleted ToDo")


def example_2_set_credentials():
    """Example 2: Set credentials separately."""
    print("\n=== Example 2: Set Credentials Separately ===\n")
    
    # Set credentials
    auth.set_client_credentials("user@example.com", "password")
    
    # Now access client - it will auto-authenticate
    users = auth.client.get_list("User", fields=["name", "email"])
    print(f"Found {len(users)} users using auto-authenticated client")


def example_3_api_key():
    """Example 3: Using API key."""
    print("\n=== Example 3: API Key Authentication ===\n")
    
    # Set API key
    auth.set_client_api_key("your-api-key", "your-api-secret")
    
    # Use client
    companies = auth.client.get_list("Company", fields=["name"])
    print(f"Found {len(companies)} companies")


def example_4_get_client():
    """Example 4: Get a one-off client."""
    print("\n=== Example 4: One-off Client ===\n")
    
    # Get a client with explicit credentials (doesn't affect auth.client)
    client = auth.get_client(
        username="user@example.com",
        password="password"
    )
    
    # Use it
    user = client.get_doc("User", "user@example.com")
    print(f"Got user: {user.get('full_name')}")


def example_5_session_client():
    """Example 5: Get client from session."""
    print("\n=== Example 5: Client from Session ===\n")
    
    # Login first
    session = auth.login_with_password("user@example.com", "password")
    
    # Get client using session ID
    client = auth.get_client(session_id=session.session_id)
    
    # Use it
    roles = client.get_list(
        "Has Role",
        fields=["role"],
        filters={"parent": session.user.email}
    )
    print(f"User has {len(roles)} roles")


def example_6_full_workflow():
    """Example 6: Complete workflow with client usage."""
    print("\n=== Example 6: Complete Workflow ===\n")
    
    # 1. Login
    session = auth.login_with_password("user@example.com", "password")
    print(f"1. Logged in: {session.user.email}")
    
    # 2. Use auth.client for API operations
    print("\n2. Fetching data...")
    
    # Get current user details
    user = auth.client.get_doc("User", session.user.email)
    print(f"   Full name: {user.get('full_name')}")
    print(f"   User type: {user.get('user_type')}")
    
    # List documents with filters
    print("\n3. Listing documents...")
    todos = auth.client.get_list(
        "ToDo",
        fields=["name", "description", "status"],
        filters={"owner": session.user.email},
        order_by="modified desc",
        limit_page_length=5
    )
    print(f"   Found {len(todos)} todos")
    for todo in todos:
        print(f"   - {todo.get('description')} [{todo.get('status')}]")
    
    # Create a new document
    print("\n4. Creating document...")
    new_doc = auth.client.insert({
        "doctype": "Note",
        "title": "Test Note",
        "content": "Created via frappe-auth-bridge"
    })
    print(f"   Created Note: {new_doc.get('name')}")
    
    # Make an API call
    print("\n5. Making API call...")
    result = auth.client.get_api("frappe.client.get_list", {
        "doctype": "User",
        "fields": '["name"]',
        "limit_page_length": 5
    })
    print(f"   API result: {len(result)} users")
    
    # 6. Logout
    print("\n6. Logging out...")
    auth.logout(session.session_id)
    print("   ✓ Logged out successfully")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        example = sys.argv[1]
        examples = {
            "1": example_1_after_login,
            "2": example_2_set_credentials,
            "3": example_3_api_key,
            "4": example_4_get_client,
            "5": example_5_session_client,
            "6": example_6_full_workflow,
        }
        
        if example in examples:
            examples[example]()
        else:
            print("Available examples: 1, 2, 3, 4, 5, 6")
    else:
        print("Usage: python client_example.py [1-6]")
        print("\nExamples:")
        print("  1 - Client after login")
        print("  2 - Set credentials separately")
        print("  3 - API key authentication")
        print("  4 - One-off client")
        print("  5 - Client from session")
        print("  6 - Complete workflow")
