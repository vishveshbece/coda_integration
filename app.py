import os
import uuid
import json
import logging
from flask import Flask, request, jsonify, redirect
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

import requests

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# -----------------------------------------------------------
# ZOHO CONFIG
# -----------------------------------------------------------
ZOHO = {
    "AUTH_URL": "https://accounts.zoho.com/oauth/v2/auth",
    "TOKEN_URL": "https://accounts.zoho.com/oauth/v2/token",
    "CLIENT_ID": "1000.32B09XAMP2H3NPXDRTXQAQ5LTY36ZJ",
    "CLIENT_SECRET": "167da2a5601f04fb02b17e42d9a23eb58d1ea46779",
    "REDIRECT_URI": "https://coda-integration.onrender.com/oauth/callback",
    "SCOPE": "ZohoCliq.Messages.ALL,ZohoCliq.Webhooks.CREATE,ZohoCliq.MediaSession.READ,ZohoCliq.Attachments.READ,ZohoCliq.Chats.READ",
}

# -----------------------------------------------------------
# LOCAL JSON FILE AS DATABASE
# -----------------------------------------------------------
DB_FILE = "users.json"

def load_db():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({}, f)
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

# -----------------------------------------------------------
# EXCHANGE AUTH CODE FOR TOKENS
# -----------------------------------------------------------
def exchange_code_for_tokens(auth_code):
    data = {
        "grant_type": "authorization_code",
        "client_id": ZOHO["CLIENT_ID"],
        "client_secret": ZOHO["CLIENT_SECRET"],
        "redirect_uri": ZOHO["REDIRECT_URI"],
        "code": auth_code,
    }

    response = requests.post(ZOHO["TOKEN_URL"], data=data)
    logging.info("TOKEN EXCHANGE RESPONSE: %s", response.text)

    if response.status_code != 200:
        return None

    token_data = response.json()
    expiry = datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])

    return {
        "access_token": token_data["access_token"],
        "refresh_token": token_data.get("refresh_token"),
        "expires_at": expiry.isoformat(),
    }

# -----------------------------------------------------------
# REFRESH ACCESS TOKEN
# -----------------------------------------------------------
def refresh_access_token(refresh_token):
    data = {
        "grant_type": "refresh_token",
        "client_id": ZOHO["CLIENT_ID"],
        "client_secret": ZOHO["CLIENT_SECRET"],
        "refresh_token": refresh_token,
    }

    response = requests.post(ZOHO["TOKEN_URL"], data=data)
    logging.info("REFRESH RESPONSE: %s", response.text)

    if response.status_code != 200:
        return None

    token_data = response.json()
    expiry = datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])

    return {
        "access_token": token_data["access_token"],
        "expires_at": expiry.isoformat(),
    }

# -----------------------------------------------------------
# VALID TOKEN HANDLER
# -----------------------------------------------------------
def get_valid_access_token(org_id, user_id):
    db = load_db()

    if org_id not in db or user_id not in db[org_id]:
        return None

    user = db[org_id][user_id]
    expires = datetime.fromisoformat(user["expires_at"])

    if expires > datetime.now(timezone.utc) + timedelta(seconds=60):
        return user["access_token"]

    logging.info("Access token expired. Refreshing...")

    new_data = refresh_access_token(user["refresh_token"])
    if not new_data:
        return None

    user["access_token"] = new_data["access_token"]
    user["expires_at"] = new_data["expires_at"]
    save_db(db)

    return user["access_token"]

# ======================================================
# 1️⃣ UPDATED OAUTH START — handles already logged in users
# ======================================================
@app.route("/oauth/start", methods=["GET"])
def oauth_start():
    org = request.args.get("cliq_org_id")
    user = request.args.get("cliq_user_id")

    if not org or not user:
        return jsonify({"error": "Missing org/user"}), 400

    db = load_db()

    # -------------------------------------------------
    # USER ALREADY LOGGED IN
    # -------------------------------------------------
    if org in db and user in db[org]:
        logging.info("User already logged in. Refreshing token...")

        refresh_token_value = db[org][user].get("refresh_token")

        if refresh_token_value:
            new_token_data = refresh_access_token(refresh_token_value)

            if new_token_data:
                db[org][user]["access_token"] = new_token_data["access_token"]
                db[org][user]["expires_at"] = new_token_data["expires_at"]
                save_db(db)

                return jsonify({
                    "status": "already_logged_in",
                    "message": "You are already logged in. Token refreshed.",
                    "access_token": new_token_data["access_token"][:12] + "..."
                })

        logging.info("Refresh token missing → forcing new login")

    # -------------------------------------------------
    # NEW LOGIN → GENERATE AUTH LINK
    # -------------------------------------------------
    state = f"{org}_{user}_{uuid.uuid4().hex}"

    params = {
        "client_id": ZOHO["CLIENT_ID"],
        "response_type": "code",
        "scope": ZOHO["SCOPE"],
        "redirect_uri": ZOHO["REDIRECT_URI"],
        "access_type": "offline",
        "state": state,
    }

    auth_url = ZOHO["AUTH_URL"] + "?" + urlencode(params)

    return jsonify({
        "status": "new_login_required",
        "auth_url": auth_url,
        "message": "Please authorize this integration."
    })

# ======================================================
# 2️⃣ OAUTH CALLBACK
# ======================================================
@app.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return jsonify({"error": "Invalid callback"}), 400

    org_id, user_id, _ = state.split("_", 2)

    token_data = exchange_code_for_tokens(code)
    if not token_data:
        return jsonify({"error": "Token exchange failed"}), 400

    db = load_db()
    if org_id not in db:
        db[org_id] = {}

    db[org_id][user_id] = token_data
    save_db(db)

    return jsonify({
        "message": "Authorization successful.",
        "org_id": org_id,
        "user_id": user_id
    })

# ======================================================
# 3️⃣ TEST ROUTE
# ======================================================
@app.route("/api/test", methods=["GET"])
def test_api():
    org = request.args.get("cliq_org_id")
    user = request.args.get("cliq_user_id")

    token = get_valid_access_token(org, user)
    if not token:
        return jsonify({"error": "No valid token"}), 401

    return jsonify({
        "success": True,
        "token": token[:12] + "..."
    })

# ======================================================
# FLASK RUN
# ======================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
