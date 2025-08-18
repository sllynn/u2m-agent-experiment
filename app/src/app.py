import os
import requests
import msal
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --- Configuration ---
# Load these from environment variables or a secure config store.
TENANT_ID = os.environ.get("TENANT_ID", "YOUR_TENANT_ID")

# ==> BACKEND App Registration Config
BACKEND_CLIENT_ID = os.environ.get("BACKEND_CLIENT_ID", "YOUR_MIDDLE_TIER_APP_CLIENT_ID")
BACKEND_CLIENT_SECRET = os.environ.get("BACKEND_CLIENT_SECRET", "YOUR_MIDDLE_TIER_APP_CLIENT_SECRET")

# ==> FRONTEND (SPA) App Registration Config
# These are now read from the environment and served to the JS front-end.
SPA_CLIENT_ID = os.environ.get("SPA_CLIENT_ID", "YOUR_SPA_APP_CLIENT_ID")

DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST", "https://<your-databricks-workspace>.azuredatabricks.net")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
DATABRICKS_SCOPE = ["2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default"]

# --- MSAL Setup ---
# Initialize the MSAL Confidential Client Application.
msal_app = msal.ConfidentialClientApplication(
    client_id=BACKEND_CLIENT_ID,
    authority=AUTHORITY,
    client_credential=BACKEND_CLIENT_SECRET,
)

# --- FastAPI App Initialization ---
app = FastAPI()

# Configure CORS
origins = ["http://localhost", "http://localhost:8000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Pydantic Models for Configuration ---
class SpaConfig(BaseModel):
    clientId: str
    authority: str
    apiScope: str

# --- API Endpoints ---

@app.get("/auth/config", response_model=SpaConfig)
def get_spa_config():
    """
    Provides the necessary MSAL configuration to the front-end.
    This endpoint is unauthenticated.
    """
    return SpaConfig(
        clientId=SPA_CLIENT_ID,
        authority=AUTHORITY,
        apiScope=f"api://{BACKEND_CLIENT_ID}/.default"
    )

@app.get("/api/list-databricks-clusters")
def list_databricks_clusters(token: str = Depends(oauth2_scheme)):
    """
    Performs the On-Behalf-Of flow.
    """
    result = msal_app.acquire_token_on_behalf_of(
        user_assertion=token,
        scopes=DATABRICKS_SCOPE
    )

    if "error" in result:
        print(f"MSAL Error: {result.get('error_description')}")
        raise HTTPException(
            status_code=401,
            detail=result.get("error_description", "Failed to acquire token on behalf of user.")
        )

    databricks_access_token = result['access_token']
    api_url = f"{DATABRICKS_HOST}/api/2.0/clusters/list"
    headers = {"Authorization": f"Bearer {databricks_access_token}"}

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        raise HTTPException(
            status_code=err.response.status_code,
            detail=f"Error calling Databricks API: {err.response.text}"
        )

# --- Static File Serving ---
# IMPORTANT: This must come AFTER your API routes.
app.mount("/", StaticFiles(directory="static", html=True), name="static")

