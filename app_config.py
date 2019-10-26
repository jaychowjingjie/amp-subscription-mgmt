import os
# Our Quickstart uses this placeholder
# In your production app, we recommend you to use other ways to store your secret,
# such as KeyVault, or environment variable as described in Flask's documentation here
# https://flask.palletsprojects.com/en/1.1.x/config/#configuring-from-environment-variables
# CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# if not CLIENT_SECRET:
#     raise ValueError("Need to define CLIENT_SECRET environment variable")

# You can replace tenant id with your azure id
AUTHORITY = "https://login.microsoftonline.com/8c96ad13-9dee-4537-8366-252bd0cd9f3f"
CLIENT_ID = "9a9c3f58-f77c-4c0b-9451-80565711157c"
CLIENT_SECRET = "nnX-5-IS]tgiLlN2L4?YeSR0iz-4FUM]" 

M_AUTHORITY = "https://login.microsoftonline.com/6ebb869a-f2fc-455f-b3c3-c82173d556ea"
M_CLIENT_ID = "84aca647-1340-454b-923c-a21a9003b28e"
M_CLIENT_SECRET = "Ru]pNY1uNB0OwvTWuslMdgX5SUT/D4-+" 

REDIRECT_PATH = "/getAToken"  # It will be used to form an absolute URL
    # And that absolute URL must match your app's redirect_uri set in AAD

# For calling the Graph api
ENDPOINT = 'https://graph.microsoft.com/v1.0/users'  # This resource requires no admin consent

# You can find the proper permission names from this document
# https://docs.microsoft.com/en-us/graph/permissions-reference
SESSION_TYPE = "filesystem"  # So token cache will be stored in server-side session
SCOPE = [""]
# For calling the market place api
MARKETPLACEAPI_ENDPOINT = 'https://marketplaceapi.microsoft.com/api/saas/subscriptions?api-version=2018-08-31'

