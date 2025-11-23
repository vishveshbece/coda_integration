import os
from flask import Flask, request, jsonify
import json
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- WARNING: IN-MEMORY STORAGE ---
# For production, replace this dictionary with a secure, encrypted database!
# Keys are stored here only while the server is running.
SECURE_KEY_STORE = {} 

# --- HELPER FUNCTIONS ---

def mock_key_validation(api_key):
    """
    Mocks the validation of a third-party API key.
    In a real app, this would involve a test call to the third-party API.
    """
    # Simple mock check: key must be at least 15 characters long
    return len(api_key) >= 15 

# --- ENDPOINT A: KEY STORAGE (Used by Cliq Setup Handler) ---

@app.route('/api/store-key', methods=['POST'])
def store_third_party_key():
    """
    Receives the client's third-party API Key and securely stores it.
    """
    try:
        data = request.json
    except json.JSONDecodeError:
        logging.error("Received non-JSON data")
        return jsonify({"message": "Invalid JSON format"}), 400

    cliq_org_id = data.get('cliq_org_id')
    third_party_key = data.get('third_party_key')

    if not cliq_org_id or not third_party_key:
        logging.warning(f"Missing data for storage. Org ID: {cliq_org_id}")
        return jsonify({"message": "Missing organization ID or API key in request"}), 400

    # 1. Validate the key (using the mock function)
    if not mock_key_validation(third_party_key):
        return jsonify({"message": "API Key is invalid (Mock validation failed)"}), 401
    
    # 2. Store the Key Securely (Simulated Storage)
    SECURE_KEY_STORE[cliq_org_id] = third_party_key
    logging.info(f"Key stored successfully for Org ID: {cliq_org_id}")

    return jsonify({"message": "Third-Party API Key stored successfully"}), 200

# --- ENDPOINT B: DYNAMIC DATA RETRIEVAL (Used by Cliq Command Handler) ---

@app.route('/api/get-data', methods=['GET'])
def get_dynamic_data():
    """
    Retrieves the stored key dynamically and returns a dynamic response,
    proving the multi-tenant architecture is working.
    """
    # Cliq Deluge sends cliq_org_id as a query parameter in the GET request
    cliq_org_id = request.args.get('cliq_org_id')
    
    if not cliq_org_id:
        return jsonify({"message": "Missing cliq_org_id parameter. Setup required."}), 400

    # 1. Retrieve the stored key dynamically for the requesting organization
    third_party_key = SECURE_KEY_STORE.get(cliq_org_id)

    if not third_party_key:
        logging.warning(f"Key not found for Org ID: {cliq_org_id}")
        return jsonify({"message": "Setup incomplete. API Key not found for this organization."}), 404

    # 2. GENERATE DYNAMIC MOCK RESPONSE
    # This response is unique to the requesting client (cliq_org_id)
    dynamic_response = f"Success! This response is dynamically generated for organization: {cliq_org_id}. Your key is secured."

    logging.info(f"Dynamic response generated for Org ID: {cliq_org_id}")
    
    # 3. Return the processed data back to Cliq
    return jsonify({
        "response_data": dynamic_response,
        "source_org_id": cliq_org_id
    }), 200


if __name__ == '__main__':
    # Render uses the PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)