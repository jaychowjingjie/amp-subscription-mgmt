import os
from dotenv import load_dotenv

# Load the values from .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')  # Path to .env file
load_dotenv(dotenv_path)

# Our Quickstart uses this placeholder
# In your production app, we recommend you to use other ways to store your secret,
# such as KeyVault, or environment variable as described in Flask's documentation here
# https://flask.palletsprojects.com/en/1.1.x/config/#configuring-from-environment-variables
# CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# if not CLIENT_SECRET:
#     raise ValueError("Need to define CLIENT_SECRET environment variable")

# Application login
TENANT_ID = os.getenv('TENANT_ID')
if not TENANT_ID:
     raise ValueError("Need to define TENANT_ID environment variable")
CLIENT_ID = os.getenv('CLIENT_ID')
if not CLIENT_ID:
     raise ValueError("Need to define CLIENT_ID environment variable")
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
if not CLIENT_SECRET:
     raise ValueError("Need to define CLIENT_SECRET environment variable")

# For calling the market place api
MARKETPLACEAPI_TENANTID = os.getenv('MARKETPLACEAPI_TENANTID')
if not MARKETPLACEAPI_TENANTID:
     raise ValueError("Need to define MARKETPLACEAPI_TENANTID environment variable")
MARKETPLACEAPI_CLIENT_ID = os.getenv('MARKETPLACEAPI_CLIENT_ID')
if not MARKETPLACEAPI_CLIENT_ID:
     raise ValueError("Need to define MARKETPLACEAPI_CLIENT_ID environment variable")
MARKETPLACEAPI_CLIENT_SECRET = os.getenv('MARKETPLACEAPI_CLIENT_SECRET')
if not MARKETPLACEAPI_CLIENT_SECRET:
     raise ValueError("Need to define MARKETPLACEAPI_CLIENT_SECRET environment variable")
MARKETPLACEAPI_API_VERSION = os.getenv('MARKETPLACEAPI_API_VERSION')
if not MARKETPLACEAPI_API_VERSION:
     raise ValueError("Need to define MARKETPLACEAPI_API_VERSION environment variable")

STORAGE_CONNECTION_STRING = os.getenv('STORAGE_CONNECTION_STRING')
if not STORAGE_CONNECTION_STRING:
     raise ValueError("Need to define STORAGE_CONNECTION_STRING environment variable")
WEBHOOK_OPS_STORAGE_TABLE_NAME = os.getenv('WEBHOOK_OPS_STORAGE_TABLE_NAME')
if not WEBHOOK_OPS_STORAGE_TABLE_NAME:
     raise ValueError("Need to define WEBHOOK_OPS_STORAGE_TABLE_NAME environment variable")
ISV_OPS_STORAGE_TABLE_NAME = os.getenv('ISV_OPS_STORAGE_TABLE_NAME')
if not ISV_OPS_STORAGE_TABLE_NAME:
     raise ValueError("Need to define ISV_OPS_STORAGE_TABLE_NAME environment variable")

# It will be used to form an absolute URL
# And that absolute URL must match your app's redirect_uri set in AAD
REDIRECT_PATH = "/getAToken"  
SESSION_TYPE = "filesystem"  # So token cache will be stored in server-side session
SCOPE = [""]
AUTHORITY = "https://login.microsoftonline.com/"
MARKETPLACEAPI_ENDPOINT = 'https://marketplaceapi.microsoft.com/api/saas/subscriptions'
MARKETPLACEAPI_OPERATIONS_ENDPOINT = 'https://marketplaceapi.microsoft.com/api/saas/operations'
MARKETPLACEAPI_RESOURCE="62d94f6c-d599-489b-a797-3e10e42fbe22"
