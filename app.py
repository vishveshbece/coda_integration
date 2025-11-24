import os
import uuid
import json
import logging
import requests # Necessary for simulating real API calls to Zoho
from urllib.parse import urlencode, urljoin # Helper for building clean URLs
from flask import Flask, request, jsonify, redirect
from datetime import datetime, timedelta, timezone

# Initialize Flask App
app = Flask(__name__)

# Configure Logging for Render/Production Environment
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- ZOHO CONFIGURATION & SECRETS ---
# NOTE: Replace these mock values with your actual credentials from the Zoho Developer Console.
# The REDIRECT_URI MUST match the one registered in the Zoho console.
THIRD_PARTY_CONFIG = {
    # Actual Zoho Accounts URL
    "ZOHO_ACCOUNTS_URL": "https://accounts.zoho.com",
    "CLIENT_ID": "1000.32B09XAMP2H3NPXDRTXQAQ5LTY36ZJ", 
    "CLIENT_SECRET": "167da2a5601f04fb02b17e42d9a23eb58d1ea46779",
    "REDIRECT_URI": "https://coda-integration.onrender.com/oauth/callback", # Update this!
    # Scopes needed for Cliq functionality
    "SCOPE": "ZohoCliq.Messages.ALL,ZohoCliq.Webhooks.CREATE,ZohoCliq.MediaSession.READ,ZohoCliq.Attachments.READ,ZohoCliq.Chats.READ",
    
    # OAuth endpoints
    "AUTH_URL": "https://accounts.zoho.com/oauth/v2/auth",
    "TOKEN_URL": "https://accounts.zoho.com/oauth/v2/token",
}

# --- SECURE MOCK DATABASE STRUCTURE (In-Memory) ---
# WARNING: This is volatile. Use Firestore/PostgreSQL for production.

# Global store for Org-level API Keys (Multi-Tenant)
ORG_KEY_STORE = {} 

# Global store for User-level OAuth Tokens (Multi-User)
# Structure: {cliq_org_id: {cliq_user_id: {token_data}}}
USER_TOKEN_DATABASE = {} 

# --- HELPER FUNCTIONS ---

def mock_key_validation(api_key):
    """ Mocks validation for static API key. Must be 15+ chars. """
    return len(api_key) >= 15 

def exchange_code_for_tokens(auth_code):
    """
    Simulates the POST request to Zoho to exchange the temporary Authorization Code
    for the long-lived Refresh Token and short-lived Access Token.
    """
    token_url = THIRD_PARTY_CONFIG["TOKEN_URL"]
    
    post_data = {
        'code': auth_code,
        'client_id': THIRD_PARTY_CONFIG["CLIENT_ID"],
        'client_secret': THIRD_PARTY_CONFIG["CLIENT_SECRET"],
        'redirect_uri': THIRD_PARTY_CONFIG["REDIRECT_URI"],
        'grant_type': 'authorization_code',
        'scope': THIRD_PARTY_CONFIG["SCOPE"]
    }
    
    try:
        # In a real environment, you would use requests.post here
        # response = requests.post(token_url, data=post_data)
        # response.raise_for_status() # Raises HTTPError for bad responses
        # data = response.json()

        # MOCK RESPONSE (since we cannot call Zoho API here)
        if auth_code.startswith("cliq_auth_code_"):
            data = {
                "access_token": f"ACCESS-{uuid.uuid4().hex[:16]}", 
                "refresh_token": f"REFRESH-{uuid.uuid4().hex[:16]}",
                "expires_in": 3600 # seconds
            }
        else:
            return None # Simulate failed exchange

        now = datetime.now(timezone.utc)
        data['expires_at'] = (now + timedelta(seconds=data['expires_in'] - 300)).isoformat() # 5 min buffer
        return data

    except Exception as e:
        logging.error(f"Zoho Code Exchange Failed: {e}")
        return None

def refresh_access_token(refresh_token):
    """
    Simulates the POST request to Zoho to use the Refresh Token 
    to obtain a new Access Token.
    """
    token_url = THIRD_PARTY_CONFIG["TOKEN_URL"]
    
    post_data = {
        'refresh_token': refresh_token, 
        'client_id': THIRD_PARTY_CONFIG["CLIENT_ID"],
        'client_secret': THIRD_PARTY_CONFIG["CLIENT_SECRET"],
        'grant_type': 'refresh_token' 
    }
    
    try:
        # In a real environment, you would use requests.post here
        # response = requests.post(token_url, data=post_data)
        # response.raise_for_status() 
        # data = response.json()

        # MOCK REFRESH RESPONSE
        if refresh_token.startswith("REFRESH-"):
            data = {
                "access_token": f"ACCESS-{uuid.uuid4().hex[:16]}", 
                "expires_in": 3600 # seconds
            }
        else:
            return None

        now = datetime.now(timezone.utc)
        data['expires_at'] = (now + timedelta(seconds=data['expires_in'] - 300)).isoformat() # 5 min buffer
        return data
        
    except Exception as e:
        logging.error(f"Zoho Token Refresh Failed: {e}")
        return None

def get_valid_access_token(org_id, user_id):
    """ 
    Retrieves user's tokens, refreshes if expired using Zoho logic.
    Returns the valid Access Token or None if unauthorized.
    """
    if org_id not in USER_TOKEN_DATABASE or user_id not in USER_TOKEN_DATABASE[org_id]:
        return None # Unauthorized
    
    user_data = USER_TOKEN_DATABASE[org_id][user_id]
    
    # 1. Check if the current Access Token is still valid (1-minute buffer)
    try:
        expiry_time = datetime.fromisoformat(user_data["expires_at"])
    except:
        logging.error("Token expiry time format error.")
        return None
        
    # If the current token expires more than 1 minute from now, use it.
    if expiry_time > datetime.now(timezone.utc) + timedelta(minutes=1):
        logging.info("Using existing valid Access Token.")
        return user_data["access_token"]
        
    # 2. Access Token is expired or near expiry -> Use Refresh Token
    logging.info("Access Token expired or nearing expiry. Attempting refresh.")
    
    # Use the Zoho-specific refresh function
    new_tokens = refresh_access_token(user_data["refresh_token"])
    
    if new_tokens:
        # Update the database with the new token details
        user_data["access_token"] = new_tokens["access_token"]
        user_data["expires_at"] = new_tokens["expires_at"]
        logging.info("Token successfully refreshed and stored.")
        return new_tokens["access_token"]
    
    # Refresh failed
    logging.error("Token refresh failed. Re-authorization required.")
    return None

# --- ENDPOINT A: ORGANIZATION SETUP (Multi-Tenant) ---

@app.route('/api/store-org-key', methods=['POST'])
def store_third_party_key():
    """ 
    Receives and stores the organization's static API Key. 
    This is for organization-wide tasks.
    """
    try:
        data = request.json
        cliq_org_id = data.get('cliq_org_id')
        third_party_key = data.get('third_party_key')
    except (json.JSONDecodeError, AttributeError):
        return jsonify({"message": "Invalid JSON format or missing data"}), 400

    if not cliq_org_id or not third_party_key:
        return jsonify({"message": "Missing organization ID or API key"}), 400

    if not mock_key_validation(third_party_key):
        return jsonify({"message": "API Key is invalid (Must be 15+ characters)"}), 401
    
    ORG_KEY_STORE[cliq_org_id] = third_party_key
    logging.info(f"Org Key stored successfully for Org ID: {cliq_org_id}")

    return jsonify({"message": "Organization API Key stored successfully"}), 200


# --- ENDPOINT B: START USER AUTHORIZATION FLOW (Multi-User Step 1) ---

@app.route('/oauth/start', methods=['GET'])
def start_oauth_flow():
    """ 
    Initiates the OAuth 2.0 Authorization Code Grant Flow for Zoho.
    """
    cliq_org_id = request.args.get('cliq_org_id')
    cliq_user_id = request.args.get('cliq_user_id')

    if not cliq_org_id or not cliq_user_id:
        return jsonify({"message": "Missing context parameters (org_id, user_id)"}), 400

    # The 'state' parameter carries the context securely across the third-party redirect
    state = f"{cliq_org_id}_{cliq_user_id}_{uuid.uuid4().hex}" 
    
    query_params = {
        'scope': THIRD_PARTY_CONFIG["SCOPE"],
        'client_id': THIRD_PARTY_CONFIG["CLIENT_ID"],
        'response_type': 'code',
        'redirect_uri': THIRD_PARTY_CONFIG["REDIRECT_URI"],
        'access_type': 'offline', # Crucial for getting the permanent refresh token
        'state': state
    }

    # Construct the Zoho Authorization URL
    auth_url = THIRD_PARTY_CONFIG["AUTH_URL"] + "?" + urlencode(query_params)

    logging.info(f"Generated Zoho OAuth URL for {cliq_user_id}: {auth_url}")
    # 

    return jsonify({
        "message": "User authorization required. Redirect user to the URL below.",
        "redirect_url": auth_url,
        "next_step_simulation": f"To simulate successful authorization, manually hit: {request.host_url}oauth/callback?code=cliq_auth_code_{cliq_user_id}&state={state}"
    }), 202 

# --- ENDPOINT C: OAUTH CALLBACK (Multi-User Step 2: Token Exchange) ---

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    """
    Receives the Authorization Code and exchanges it for the Refresh Token
    by simulating the POST request to Zoho's token endpoint.
    """
    auth_code = request.args.get('code')
    state = request.args.get('state') 
    
    if not auth_code or not state:
        return jsonify({"message": "Missing authorization code or state parameter"}), 400

    # 1. Validate and extract context from the state parameter
    try:
        # We need to split the state which looks like 'org_id_user_id_randomhash'
        cliq_org_id, cliq_user_id, _ = state.rsplit('_', 2)
    except ValueError:
        return jsonify({"message": "Invalid state parameter format."}), 400

    # 2. Simulate the Token Exchange using Zoho logic
    token_data = exchange_code_for_tokens(auth_code)

    if not token_data:
        logging.error(f"Zoho Token exchange failed for user {cliq_user_id}.")
        return jsonify({"message": "Zoho Token exchange failed."}), 401

    # 3. Securely Store the Tokens
    if cliq_org_id not in USER_TOKEN_DATABASE:
        USER_TOKEN_DATABASE[cliq_org_id] = {}

    USER_TOKEN_DATABASE[cliq_org_id][cliq_user_id] = {
        "refresh_token": token_data["refresh_token"],
        "access_token": token_data["access_token"],
        "expires_at": token_data["expires_at"],
        "authorization_status": "AUTHORIZED"
    }

    logging.info(f"User {cliq_user_id} successfully authorized. Refresh Token stored.")
    
    return jsonify({
        "message": f"Zoho Authorization successful for user {cliq_user_id}.",
        "user": cliq_user_id,
        "org": cliq_org_id,
        "action": "The user can now return to Cliq to use the features."
    }), 200

# --- ENDPOINT D: RETRIEVE PERSONALIZED DATA (Usage: Multi-User Check) ---

@app.route('/api/get-user-data', methods=['GET'])
def get_user_personalized_data():
    """
    The core usage endpoint. It ensures the user is authorized, handles token refresh,
    and uses the valid Access Token (Zoho-oauthtoken) to fetch personalized data.
    """
    cliq_org_id = request.args.get('cliq_org_id')
    cliq_user_id = request.args.get('cliq_user_id')
    
    if not cliq_org_id or not cliq_user_id:
        return jsonify({"message": "Missing cliq_org_id or cliq_user_id parameter."}), 400

    # 1. Get a valid Access Token (handles retrieval AND refresh logic)
    valid_access_token = get_valid_access_token(cliq_org_id, cliq_user_id)

    if not valid_access_token:
        # 2. If token is missing or refresh failed, prompt for re-authorization
        return jsonify({
            "message": "Access denied. User token is missing or expired and requires re-authorization.",
            "auth_required": True,
            "action": f"Call /oauth/start with cliq_org_id and cliq_user_id to start authorization."
        }), 403 # Forbidden
        
    # 3. Success: Use the valid Access Token (Zoho-oauthtoken)
    # This is where you would make the actual Cliq API call, e.g.:
    # headers = {'Authorization': f'Zoho-oauthtoken {valid_access_token}'}
    # response = requests.get('https://cliq.zoho.com/api/v2/channels', headers=headers)
    
    current_token_status = USER_TOKEN_DATABASE[cliq_org_id][cliq_user_id]

    dynamic_response = {
        "status": "Success - Token Validated and Refreshed",
        "message": "Personalized data successfully retrieved.",
        "user_context": f"Organization: {cliq_org_id}, User: {cliq_user_id}",
        "data_payload": f"API call would be made with token: {valid_access_token[:10]}...",
        "token_expiry": current_token_status["expires_at"],
        "api_usage_example": "GET https://cliq.zoho.com/api/v2/channels with Header: Authorization: Zoho-oauthtoken [Access Token]"
    }
    
    return jsonify(dynamic_response), 200


if __name__ == '__main__':
    # Render uses the PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)