import uuid
from flask import Flask, render_template, session, request, redirect, url_for, jsonify
from flask_session import Session
import msal
import app_config
import constant
import utils
import amprepo

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)


@app.route("/")
def login():
    if not session.get("user"):
        session["state"] = str(uuid.uuid4())
        auth_url = utils._build_msal_app().get_authorization_request_url(
                    [],  # openid+profile are included by default
                    state=session["state"],
                    redirect_uri=url_for("authorized", _external=True, _scheme=app_config.HTTP_SCHEME))

        return redirect(auth_url, code=302)
    else:
        subscriptions = amprepo.get_subscriptions()
        return render_template('index.html', user=session["user"], subscriptions=subscriptions, version=msal.__version__)

@app.route(app_config.REDIRECT_PATH)  # your app's redirect_uri set in AAD
def authorized():
    if request.args.get('state') == session.get("state"):
        cache = utils._load_cache()
        result = utils._build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=[],  # Misspelled scope would cause an HTTP 400 error here
            redirect_uri=url_for("authorized", _external=True, _scheme=app_config.HTTP_SCHEME))
        if "error" in result:
            return "Login failure: %s, %s" % (
                result["error"], result.get("error_description"))
        session["user"] = result.get("id_token_claims")
        utils._save_cache(cache)
    return redirect(url_for("login"))


@app.route("/webhook", methods=['POST'])
def webhook():

    try:
        utils._validate_jwt_token(request.headers.get('Authorization'))
        # connect to table storage
        request_payload = request.get_json(force=True)
        request_payload["PartitionKey"] = request_payload['subscriptionId']
        request_payload["RowKey"] = request_payload['id']
        utils._store_in_azure_table(app_config.WEBHOOK_OPS_STORAGE_TABLE_NAME, request_payload)
        return jsonify(), 201
    except Exception as e:
        app.logger.error(e)
        return jsonify("An exception occurred"), 500

@app.route("/landingpage")
def landingpage():
    if not utils._user_is_authenticated():
        return redirect(url_for("login"))
    token = request.args.get('token')
    subscription = amprepo.get_subscriptionid_by_token(token)
    if not token or 'id' not in subscription:
        return render_template(constant.ERROR_PAGE, user=session["user"])  
    subscription_data = amprepo.get_subscription(subscription['id'])
    plans = amprepo.get_availableplans(subscription['id'])
    
    return render_template(constant.MANAGE_SUBSCRIPTION_PAGE, user=session["user"], subscription=subscription_data, available_plans=plans)


@app.route("/edit/<subscriptionid>")
def edit(subscriptionid):
    if not utils._user_is_authenticated():
        return redirect(url_for("login"))
    subscription = amprepo.get_subscription(subscriptionid)
    plans = amprepo.get_availableplans(subscriptionid)
    return render_template(constant.MANAGE_SUBSCRIPTION_PAGE, user=session["user"], subscription=subscription, available_plans=plans)

@app.route("/update", methods=['POST'])
def updatesubscription():
    if not utils._user_is_authenticated():
        return redirect(url_for("login"))
    selected_subscription = request.form['subscription_id']
    
    if 'activate' in request.form:
        selected_plan = request.form['subscription_plan_id']
        response = amprepo.activate_subscriptionplan(selected_subscription, selected_plan)
    elif 'update' in request.form:
        selected_plan = request.form['selectedplan']
        response = amprepo.update_subscriptionplan(selected_subscription, selected_plan)
    else:
        return redirect(url_for(constant.ERROR_PAGE))

    if response.status_code == 202 or response.status_code:
        return redirect(url_for("login"))
    else:
        return render_template(constant.ERROR_PAGE, user=session["user"], response_statuscode=response.status_code)
    
@app.route("/operations/<subscriptionid>")
def operations(subscriptionid):
    if not utils._user_is_authenticated():
        return redirect(url_for("login"))
    sub_operations = amprepo.get_sub_operations(subscriptionid)
    return render_template(constant.SUBSCRIPTION_OPERATIONS_PAGE, user=session["user"], operations=sub_operations)

# todo change quantity
@app.route("/updateoperation/<operationid>")
def updateoperation(operationid):
    if not utils._user_is_authenticated():
        return redirect(url_for("login"))
    subid = request.args.get('subid')
    planid = request.args.get('planid')
    quantity = request.args.get('quantity')
    status = request.args.get('status')
    request_payload = "{\"planId\": \"%s\",\"quantity\": \"%s\",\"status\": \"%s\"}" % (planid, quantity, status)
    return redirect(url_for("operations", subscriptionid=subid))

# todo delete subscription


@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        #app_config.AUTHORITY + "/" + app_config.TENANT_ID + "/oauth2/v2.0/logout" +
        app_config.AUTHORITY + "/common/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("login", _external=True, _scheme=app_config.HTTP_SCHEME))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
