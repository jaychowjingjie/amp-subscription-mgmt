import uuid
import requests
from flask import Flask, render_template, session, request, redirect, url_for, jsonify
from flask_session import Session  # https://pythonhosted.org/Flask-Session
import msal
import app_config
from azure.storage import CloudStorageAccount
from azure.storage.table import TableService, Entity
from tablestorageaccount import TableStorageAccount
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)


@app.route("/")
def login():
    if not session.get("user"):
        session["state"] = str(uuid.uuid4())
        auth_url = _build_msal_app().get_authorization_request_url(
                    [],  # Technically we can use empty list [] to just sign in,
                               # here we choose to also collect end user consent upfront
                    state=session["state"],
                    redirect_uri=url_for("authorized", _external=True))

        return redirect(auth_url, code=302)
    else:
        subscriptions = get_subscriptions()
        return render_template('index.html', user=session["user"], subscriptions= subscriptions, version=msal.__version__)

@app.route(app_config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    if request.args.get('state') == session.get("state"):
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=[],  # Misspelled scope would cause an HTTP 400 error here
            redirect_uri=url_for("authorized", _external=True))
        if "error" in result:
            return "Login failure: %s, %s" % (
                result["error"], result.get("error_description"))
        app.logger.info(result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    return redirect(url_for("login"))


@app.route("/webhook", methods = ['POST'])
def webhook():

    try:
        request_payload = request.get_json(force=True)
        request_payload["PartitionKey"] = request_payload['subscriptionId']
        request_payload["RowKey"]  = request_payload['id']
        app.logger.info(type(request_payload))
        
        try:
            # validate jwt tokens
            # https://aboutsimon.com/blog/2017/12/05/Azure-ActiveDirectory-JWT-Token-Validation-With-Python.html
            # https://github.com/RobertoPrevato/PythonJWTDemo/blob/master/demo.py
            # https://stackoverflow.com/questions/43142716/how-to-verify-jwt-id-token-produced-by-ms-azure-ad
            # https://stackoverflow.com/questions/51964173/how-to-validate-token-in-azure-ad-with-python
            #1 download openid config
            #2 get the jwks keys from jwks uri
            #3 search for token header kid in jwks keys and extract x5c(X.509 certificate chain)
            #4 extract the public key
            #5 decode the jwt 
            access_token = request.headers.get('Authorization')
            app_id = app_config.MARKETPLACEAPI_CLIENT_ID
            token_header = jwt.get_unverified_header(bearer_token)
            app.logger.info(request_headers)
            
            #jwks_uri
            #res = requests.get('https://login.microsoftonline.com/common/.well-known/openid-configuration')
            #jwk_uri = res.json()['jwks_uri']
            jwk_uri="https://login.windows.net/common/discovery/keys"
            res = requests.get(jwk_uri)
            jwk_keys = res.json()
            x5c = None

            # Iterate JWK keys and extract matching x5c chain
            for key in jwk_keys['keys']:
                if key['kid'] == token_header['kid']:
                    x5c = key['x5c']

            #create a public key from the cert made from x5c
            cert = ''.join([
            '-----BEGIN CERTIFICATE-----\n',
            x5c[0],
            '\n-----END CERTIFICATE-----\n',    
            ])
            public_key =  load_pem_x509_certificate(cert.encode(), default_backend()).public_key()

            #decode jwt using public key, if passed this step withour error, we can safely assume the token is validated
            jwt.decode(
                    access_token,
                    public_key,
                    algorithms='RS256',
                    audience=app_id,)
        except:
            return "Authentication error!", 500


        #connect to table storgae
        # https://github.com/Azure-Samples/storage-table-python-getting-started/blob/master/start.py
        account_connection_string = app_config.STORAGE_CONNECTION_STRING

        # Split into key=value pairs removing empties, then split the pairs into a dict
        config = dict(s.split('=', 1) for s in account_connection_string.split(';') if s)

        # Authentication
        account_name = config.get('AccountName')
        account_key = config.get('AccountKey')

        # Basic URL Configuration
        endpoint_suffix = config.get('EndpointSuffix')
        if endpoint_suffix == None:
            table_endpoint = config.get('TableEndpoint')
            table_prefix = '.table.'
            start_index = table_endpoint.find(table_prefix)
            end_index = table_endpoint.endswith(':') and len(table_endpoint) or table_endpoint.rfind(':')
            endpoint_suffix = table_endpoint[start_index+len(table_prefix):end_index]
        account = TableStorageAccount(account_name = account_name, connection_string = account_connection_string, endpoint_suffix=endpoint_suffix)
        table_service = account.create_table_service()
        app.logger.info(request_payload)

        # Insert the entity into the table
        print('Inserting a new entity into table - ' + app_config.STORAGE_TABLE_NAME)
        table_service.insert_entity(app_config.STORAGE_TABLE_NAME, request_payload)
        
        """query table storage
        tasks = table_service.query_entities('tasktable', filter="PartitionKey eq 'tasksSeattle'")
        for task in tasks:
            print(task.description)
            print(task.priority)"""
        print('Successfully inserted the new entity')

        return jsonify(), 201
    except:
        return jsonify("An exception occurred"), 500

@app.route("/landingpage")
def landingpage():
    if not _user_is_authenticated():
        return redirect(url_for("login"))
    subscription = get_subscription_by_token(token)
    if not token:
        return render_template('error.html', user=session["user"])  
    plans = get_availableplans(subscriptionid)
    return render_template('managesubscription.html', user=session["user"], subscription = subscription, available_plans= plans)

@app.route("/edit/<subscriptionid>")
def edit(subscriptionid):
    if not _user_is_authenticated():
        return redirect(url_for("login"))
    subscription = get_subscription(subscriptionid)
    plans = get_availableplans(subscriptionid)
    return render_template('managesubscription.html', user=session["user"], subscription = subscription, available_plans= plans)

@app.route("/update", methods=['POST'])
def updatesubscription():
    if not _user_is_authenticated():
        return redirect(url_for("login"))
    selected_subscription = request.form['subscription_id']
    selected_plan = request.form['selectedplan']
    update_subscription_response = update_subscriptionplan(selected_subscription, selected_plan)
    if update_subscription_response.status_code == 202:
        return redirect(url_for("login"))
    else:
        return render_template('error.html', user=session["user"], response_statuscode = update_subscription_response.status_code)

@app.route("/operations/<subscriptionid>")
def operations(subscriptionid):
    app.logger.info(_user_is_authenticated())
    if not _user_is_authenticated():
        return redirect(url_for("login"))
    sub_operations = get_sub_operations(subscriptionid)
    return render_template('suboperations.html', user=session["user"], operations = sub_operations)

@app.route("/updateoperation/<operationid>")
def updateoperation(operationid):
    if not _user_is_authenticated():
        return redirect(url_for("login"))
    subid = request.args.get('subid')
    planid = request.args.get('planid')
    quantity = request.args.get('quantity')
    status = request.args.get('status')
    #sub_operations = get_sub_operations(operationid)
    request_payload = "{\"planId\": \"%s\",\"quantity\": \"%s\",\"status\": \"%s\"}" % (planid, quantity, status)
    return redirect(url_for("operations", subscriptionid=subid  ))

# todo change quantity

# todo delete subscription

@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        #app_config.AUTHORITY + "/" + app_config.TENANT_ID + "/oauth2/v2.0/logout" +
        app_config.AUTHORITY + "/common/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("login", _external=True))

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

def get_subscriptions():
    subscriptions_data=  call_marketplace_api(app_config.MARKETPLACEAPI_ENDPOINT+ app_config.MARKETPLACEAPI_API_VERSION)
    return subscriptions_data
 
def get_subscription(subscription):
    subscription_data=  call_marketplace_api(  # Use token to call downstream service
        app_config.MARKETPLACEAPI_ENDPOINT +"/"+ subscription + app_config.MARKETPLACEAPI_API_VERSION)
    return subscription_data

def get_subscription_by_token(token):
    subscription_data=  call_marketplace_api(app_config.MARKETPLACEAPI_ENDPOINT +"/resolve" + app_config.MARKETPLACEAPI_API_VERSION
                                            ,resolve_token= token, resolve_url= True)
    return subscription_data

def get_availableplans(subscription):
    availableplans = call_marketplace_api(
        request_url=app_config.MARKETPLACEAPI_ENDPOINT +"/"+ subscription + "/listAvailablePlans" + app_config.MARKETPLACEAPI_API_VERSION)
    return availableplans

def update_subscriptionplan(subscription, plan_id):
    request_plan_payload = "{\"planId\": \""+ plan_id +"\" }"
    updateresponse = call_marketplace_api(app_config.MARKETPLACEAPI_ENDPOINT +"/"+ subscription +       app_config.MARKETPLACEAPI_API_VERSION,                                      
    'PATCH', 
    request_plan_payload
    )
    return updateresponse
    
def get_sub_operations(subscription):
    sub_operations_data =  call_marketplace_api(  # Use token to call downstream service
        app_config.MARKETPLACEAPI_ENDPOINT +"/"+ subscription + "/operations" + app_config.MARKETPLACEAPI_API_VERSION)
    return sub_operations_data

def get_marketplace_access_token():
    token_url = app_config.AUTHORITY + app_config.MARKETPLACEAPI_TENANTID + '/oauth2/token'
    data = {'grant_type': 'client_credentials', 
            'client_id' : app_config.MARKETPLACEAPI_CLIENT_ID, 
            'client_secret' : app_config.MARKETPLACEAPI_CLIENT_SECRET,  
            'resource':'62d94f6c-d599-489b-a797-3e10e42fbe22'}
    
    api_call_headers = {'content-type': 'application/x-www-form-urlencoded'}
    # get token for market place api
    access_token_response = requests.post(token_url, headers=api_call_headers, data=data).json()
    return access_token_response

def call_marketplace_api(request_url, request_method='GET', request_payload='', resolve_token='', resolve_url=False):
    
    # get token for market place api
    access_token_response = get_marketplace_access_token() 
    global marketplaceheaders
    if not resolve_url:
        
        marketplaceheaders={'Authorization': 'Bearer ' + access_token_response['access_token'],
                            'Content-Type': 'application/json',
                            'x-ms-requestid': str(uuid.uuid4()),
                            'x-ms-correlationid': str(uuid.uuid4())}
    else:
        global headers
        marketplaceheaders={'Authorization': 'Bearer ' + access_token_response['access_token'],
                            'x-ms-marketplace-token': resolve_token,
                            'Content-Type': 'application/json',
                            'x-ms-requestid': str(uuid.uuid4()),
                            'x-ms-correlationid': str(uuid.uuid4())}
    
    if request_method == 'GET':
        reponse_data= requests.get(  # Use token to call downstream service
                        request_url,
                        headers=marketplaceheaders
                        ).json()
        return reponse_data
    elif request_method == 'POST':
        reponse_data=requests.post(  # Use token to call downstream service
                    request_url,
                    headers=marketplaceheaders,
                    data=request_payload,
        ).json()
        return reponse_data
    elif request_method == 'PATCH':
        reponse_data=requests.patch(  # Use token to call downstream service
                    request_url,
                    headers=marketplaceheaders,
                    data=request_payload,
        )
        return reponse_data
    elif request_method == 'DELETE' :
        reponse_data=requests.get(  # Use token to call downstream service
                    request_url,
                    headers=marketplaceheaders
        ).json()
        return reponse_data


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

