import requests
from flask import session
import msal
import app_config
from tablestorageaccount import TableStorageAccount
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID,
        authority=app_config.AUTHORITY + "common",
        client_credential=app_config.CLIENT_SECRET, 
        token_cache=cache)


def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result


def _user_is_authenticated():
    token = _get_token_from_cache(app_config.SCOPE)
    if not session.get("user") or session.get("user") is None or not token or token is None:
        return False
    return True


def _validate_jwt_token(access_token):
    try:
        # validate jwt tokens
        # https://aboutsimon.com/blog/2017/12/05/Azure-ActiveDirectory-JWT-Token-Validation-With-Python.html
        # https://github.com/RobertoPrevato/PythonJWTDemo/blob/master/demo.py
        # https://stackoverflow.com/questions/43142716/how-to-verify-jwt-id-token-produced-by-ms-azure-ad
        # https://stackoverflow.com/questions/51964173/how-to-validate-token-in-azure-ad-with-python
        # https://github.com/realpython/flask-jwt-auth/
        # 1 download openid config
        # 2 get the jwks keys from jwks uri
        # 3 search for token header kid in jwks keys and extract x5c(X.509 certificate chain)
        # 4 extract the public key
        # 5 decode the jwt
        app_id = app_config.MARKETPLACEAPI_RESOURCE
        bearer, _, token = access_token.partition(' ')
        token_header = jwt.get_unverified_header(token)
        issuer = f'https://sts.windows.net/{app_config.TENANT_ID}/'  # iss
        
        # jwks_uri
        # res = requests.get('https://login.microsoftonline.com/common/.well-known/openid-configuration')
        # jwk_uri = res.json()['jwks_uri']
        jwk_uri="https://login.windows.net/common/discovery/keys"
        res = requests.get(jwk_uri)
        jwk_keys = res.json()
        x5c = None

        # Iterate JWK keys and extract matching x5c chain
        for key in jwk_keys['keys']:
            if key['kid'] == token_header['kid']:
                x5c = key['x5c']

        # create a public key from the cert made from x5c
        cert = ''.join([
        '-----BEGIN CERTIFICATE-----\n',
        x5c[0],
        '\n-----END CERTIFICATE-----\n',
        ])
        public_key = load_pem_x509_certificate(cert.encode(), default_backend()).public_key()

        # decode jwt using public key, if passed this step withour error, we can safely assume the token is validated
        jwt.decode(
                token,
                public_key,
                algorithms='RS256',
                audience=app_id,
                issuer=issuer)
    except Exception as e: 
        return f"Authentication error! {e}", 500


def _store_in_azure_table(table_name, request_payload):
    table_service = _get_azure_table_service()
    table_service.insert_entity(table_name, request_payload)


def _get_ops_from_azure_table(table_name, subscription_id):
    table_service = _get_azure_table_service()
    ops = table_service.query_entities(table_name, filter=f"PartitionKey eq '{subscription_id}'")
    return ops


def _get_azure_table_service():
    # onnect to table storgae
    # https://github.com/Azure-Samples/storage-table-python-getting-started/blob/master/start.py
    account_connection_string = app_config.STORAGE_CONNECTION_STRING

    # Split into key=value pairs removing empties, then split the pairs into a dict
    config = dict(s.split('=', 1) for s in account_connection_string.split(';') if s)

    # Authentication
    account_name = config.get('AccountName')

    # Basic URL Configuration
    endpoint_suffix = config.get('EndpointSuffix')
    if endpoint_suffix is None:
        table_endpoint = config.get('TableEndpoint')
        table_prefix = '.table.'
        start_index = table_endpoint.find(table_prefix)
        end_index = table_endpoint.endswith(':') and len(table_endpoint) or table_endpoint.rfind(':')
        endpoint_suffix = table_endpoint[start_index+len(table_prefix):end_index]
    account = TableStorageAccount(account_name=account_name, connection_string=account_connection_string, endpoint_suffix=endpoint_suffix)
    table_service = account.create_table_service()
    return table_service
