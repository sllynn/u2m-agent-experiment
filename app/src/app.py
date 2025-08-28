from databricks.sdk.core import credentials_strategy
import streamlit as st
from databricks.sdk import WorkspaceClient
from databricks.sdk.errors import DatabricksError
from databricks.sdk.oauth import Consent, get_workspace_endpoints, SessionCredentials
from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
import os
import json
import secrets
import hashlib
import base64
import requests
import traceback
from urllib.parse import urlencode, parse_qs

# --- Configuration ---
# It's recommended to set these as environment variables in your Databricks App config
DATABRICKS_HOST = os.getenv("DATABRICKS_HOST")
DATABRICKS_HOST_XWS = os.getenv("DATABRICKS_HOST_XWS")
CLIENT_ID = os.getenv("DATABRICKS_CLIENT_ID")
CLIENT_ID_XWS = os.getenv("DATABRICKS_CLIENT_ID_XWS")
CLIENT_SECRET = os.getenv("DATABRICKS_CLIENT_SECRET")
CLIENT_SECRET_XWS = os.getenv("DATABRICKS_CLIENT_SECRET_XWS")
MODEL_SERVING_ENDPOINT_NAME = os.getenv("DATABRICKS_MODEL_ENDPOINT")
UC_XWS_CONNECTION_OBJECT = os.getenv("UC_XWS_CONNECTION_OBJECT")
LOCAL_WORKSPACE_CLIENT: WorkspaceClient = None

# The base redirect URL must match one of the URLs registered in your OAuth application
app_url = os.getenv("DATABRICKS_APP_URL")
if app_url:
    # Ensure the URL has no trailing slash for a consistent match with the OAuth app config.
    BASE_REDIRECT_URL = app_url.rstrip('/')
else:
    # Fallback for local development. Ensure this matches a registered localhost URL.
    BASE_REDIRECT_URL = "http://localhost:8501"

FOREIGN_WORKSPACE_REDIRECT_URL = f"{DATABRICKS_HOST_XWS}/login/oauth/http.html"

# --- Session State Management ---
def get_session_state():
    """Initializes and returns session state variables."""
    if "local_creds" not in st.session_state:
        st.session_state.local_creds = None
    
    if "exchanged_creds" not in st.session_state:
        st.session_state.exchanged_creds = None
    
    if "foreign_creds" not in st.session_state:
        st.session_state.foreign_creds = None
    
    if "messages" not in st.session_state:
        st.session_state.messages = []
    return st.session_state

# --- Utility Functions ---
def process_query_params(query_params: dict) -> dict[str, str]:
    """
    Processes the query parameters and returns the appropriate action.
    """
    if "code" in query_params and "state" in query_params:        # if 'app_state' not in state_query:
        try:
            state_dict = json.loads(query_params['state'].replace("'", '"'))
            state_dict = {"nonce": state_dict['nonce'], "verifier": state_dict['verifier']}
        except json.JSONDecodeError:
            state_dict = {"nonce": query_params['state']}
        code = query_params['code']
        return {**state_dict, "code": code}
    else:
        st.error(f"Invalid query parameters received: {query_params}")
        st.stop()

# --- Local Workspace Authentication ---
def login_local():
    """
    Initiates a stateless login flow by manually constructing the authorization URL
    with all necessary context packed into the 'state' parameter.
    """
    # Step 1: Generate the PKCE verifier and challenge, and a CSRF token.
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("UTF-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("UTF-8").replace("=", "")
    # csrf_token = secrets.token_urlsafe(16)

    # Step 2: Pack the verifier and CSRF token into a dictionary. This is our custom state.
    # app_state_payload = {'verifier': verifier, 'csrf': csrf_token}
    
    # Step 3: JSON-serialize and URL-encode our custom state. This will be the value of the 'state' param.
    # final_state = urlencode({'app_state': json.dumps(app_state_payload)})
    nonce = secrets.token_hex(32)

    # Step 4: Manually construct the authorization URL.
    oidc_endpoints = get_workspace_endpoints(DATABRICKS_HOST)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": BASE_REDIRECT_URL,
        "scope": "all-apis",
        "state": {"nonce": nonce, "verifier": verifier},
        # "state": final_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{oidc_endpoints.authorization_endpoint}?{urlencode(params)}"

    # Step 5: Display the link to the user.
    st.markdown(f'<a href="{auth_url}" target="_self">Click here to log in to Databricks</a>', unsafe_allow_html=True)
    st.info("After authenticating, you will be redirected back here.")
    st.stop()

def exchange_local_creds() -> dict:
    """
    Token exchange for local workspace credentials.
    """

    # Step 2: Manually construct a Consent object with the necessary details
    # to perform the token exchange, including the client secret.
    # try:
    oidc_endpoints = get_workspace_endpoints(DATABRICKS_HOST)
    consent = Consent(
        state=st.session_state.local_creds['nonce'],
        verifier=st.session_state.local_creds['verifier'],
        authorization_url="", # Not needed for exchange
        redirect_url=BASE_REDIRECT_URL,
        token_endpoint=oidc_endpoints.token_endpoint,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET, # Provide the client secret for the exchange
    )
    
    # Step 3: Exchange the authorization code for credentials. The `exchange` method
    # performs the necessary state validation.
    creds = consent.exchange(code=st.session_state.local_creds['code'], state=st.session_state.local_creds['state'])
    
    # Step 4: Store the full credentials object in the session and clean up the URL.
    return creds.as_dict()
    # except DatabricksError as e:
    #     st.error(f"Failed to get access token during token exchange: {e}")
    #     st.stop()
    # except Exception as e:
    #     st.error(f"An error occurred during authentication: {e}")
    #     st.stop()

# --- Foreign Workspace Authentication ---
def login_xws():
    """
    Initiates a stateless login flow by manually constructing the authorization URL
    with all necessary context packed into the 'state' parameter.
    """

    # Step 1: Generate the PKCE verifier and challenge, and a CSRF token.
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("UTF-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("UTF-8").replace("=", "")


    # Step 2: Pack the verifier and CSRF token into a dictionary. This is our custom state.
    # app_state_payload = {'verifier': verifier, 'csrf': csrf_token}
    
    # Step 3: JSON-serialize and URL-encode our custom state. This will be the value of the 'state' param.
    # final_state = urlencode({'app_state': json.dumps(app_state_payload)})
    nonce = secrets.token_hex(32)


    xws_redirect_url = f"{BASE_REDIRECT_URL}?{urlencode({'this': st.session_state.local_creds})}"

    # Step 4: Manually construct the authorization URL.
    oidc_endpoints = get_workspace_endpoints(DATABRICKS_HOST_XWS)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID_XWS,
        "redirect_uri": xws_redirect_url,
        "scope": "all-apis",
        "state": {"nonce": nonce, "verifier": verifier},
        # "state": final_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{oidc_endpoints.authorization_endpoint}?{urlencode(params)}"

    # Step 5: Display the link to the user.
    st.markdown(f'<a href="{auth_url}" target="_self">Click here to log in to Databricks (foreign workspace)</a>', unsafe_allow_html=True)
    st.info("After authenticating, you will be redirected back here.")
    st.stop()

def write_foreign_workspace_creds(verifier: str, code: str):
    """
    Writes the foreign workspace credentials to the cross-workspace UC function.
    """
    # write foreign workspace auth code and verifier to the cross-workspace UC function
    LOCAL_WORKSPACE_CLIENT = get_local_workspace_client()

    payload = {
            "connection_user_credential": {
                "user_identity": LOCAL_WORKSPACE_CLIENT.config.username, # this user_id is the user_id which uniquely identifies the user
                "options_kvpairs": {
                "options": [
                    {
                    "key": "pkce_verifier",
                    "value": verifier
                    },
                    {
                    "key": "authorization_code",
                    "value": code
                    },
                    {
                    "key": "oauth_redirect_uri",
                    "value": FOREIGN_WORKSPACE_REDIRECT_URL
                    }
                ]
                }
            }
            }
    r = requests.post(
        f"{DATABRICKS_HOST}/api/2.1/unity-catalog/connections/{UC_XWS_CONNECTION_OBJECT}/user-credentials",
        headers=LOCAL_WORKSPACE_CLIENT.config.authenticate(),
        json=payload
    )
    if r.status_code != 200:
        st.error(f"Failed to write foreign workspace credentials: {r.text}")
        st.stop()

# --- OAuth Callback Handling ---
def handle_oauth_callback():
    """
    Handles the OAuth callback by extracting the code and our custom state from the
    URL to complete the token exchange.
    """
    query_params = st.query_params

    if not query_params:
        return

    if "this" in query_params:
        # we're already authenticated in the local workspace
        st.session_state.local_creds = query_params["this"]
        st.session_state.exchanged_creds = exchange_local_creds()
        st.session_state.foreign_creds = process_query_params(query_params)
        write_foreign_workspace_creds(st.session_state.foreign_creds['verifier'], st.session_state.foreign_creds['code'])
        # full login process complete
    else:
        st.session_state.local_creds = process_query_params(query_params)
        st.write(st.session_state.local_creds)
        st.session_state.exchanged_creds = exchange_local_creds()
        
        # local login process complete
        # update the dashboard to show the foreign workspace login button
        st.query_params.clear()
        st.session_state.show_foreign_workspace_login = True
        st.rerun()

# --- Credential Management ---
def get_credentials_strategy() -> SessionCredentials:
    """
    Returns a credentials strategy for the local workspace.
    """
    oidc_endpoints = get_workspace_endpoints(DATABRICKS_HOST)
    return SessionCredentials.from_dict(
        st.session_state.exchanged_creds,
        token_endpoint=oidc_endpoints.token_endpoint,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_url=BASE_REDIRECT_URL,
    )

def get_local_workspace_client() -> WorkspaceClient:
    """
    Returns a WorkspaceClient for the local workspace.
    """
    credentials_strategy = get_credentials_strategy()

    # Initialize WorkspaceClient with the credentials strategy.
    return WorkspaceClient(host=DATABRICKS_HOST, credentials_strategy=credentials_strategy)

# --- LLM Interaction ---
def call_llm(w_client, messages_history, new_prompt, token):
    """
    Calls the Databricks Model Serving endpoint with the user's prompt and chat history.
    """
    if not MODEL_SERVING_ENDPOINT_NAME:
        st.error("DATABRICKS_MODEL_ENDPOINT environment variable is not set.")
        return "Model endpoint not configured."

    # Combine the history with the new prompt into a list of dictionaries
    raw_messages = messages_history + [{"role": "user", "content": new_prompt}]

    # Convert the list of dictionaries into a list of ChatMessage objects
    messages_payload = [
        ChatMessage(role=ChatMessageRole(msg["role"]), content=msg["content"]) for msg in raw_messages
    ]

    try:
        response = w_client.serving_endpoints.query(
            name=MODEL_SERVING_ENDPOINT_NAME,
            messages=messages_payload,
            # extra_params={"u2mToken": token.access_token},
            max_tokens=256,
        )
        return response.choices[0].message.content
    except Exception as e:
        # Also print the exception and a full stack trace to the UI for easier debugging
        st.error(f"Error calling model endpoint: {e}")
        st.expander("Full Stack Trace").code(traceback.format_exc())
        return "Sorry, I encountered an error."

# --- Main Application UI ---
def main():
    """Main function to run the Streamlit app."""
    st.title("📄 Chat with Databricks LLM")
    st.write("This application demonstrates U2M OAuth and a chat interface with a Databricks Model Serving endpoint.")

    get_session_state()
    handle_oauth_callback()

    if st.session_state.local_creds is None:
        st.write("You are not logged in.")
        if st.button("Login with Databricks"):
            login_local()
    elif st.session_state.foreign_creds is None:
        st.write("You are not logged in to the foreign workspace.")
        if st.button("Login with Databricks (foreign workspace)"):
            login_xws()
    else:
        st.success("Successfully authenticated!")
        st.write("You can now chat with the LLM.")
        
        # Get the current token for passing to the LLM.
        current_token = get_credentials_strategy().token()

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("What would you like to ask?"):
            # Display the user's message immediately
            with st.chat_message("user"):
                st.markdown(prompt)

            # Get the response from the LLM
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                with st.spinner("Thinking..."):
                    # Pass the existing history and the new prompt to the LLM function
                    full_response = call_llm(LOCAL_WORKSPACE_CLIENT, st.session_state.messages, prompt, current_token)
                message_placeholder.markdown(full_response)
            
            # Now, add both the user prompt and the assistant response to the history for the next turn
            st.session_state.messages.append({"role": "user", "content": prompt})
            st.session_state.messages.append({"role": "assistant", "content": full_response})


if __name__ == "__main__":
    main()
