import uuid
import requests
from flask import session, redirect, url_for
import app_config
import re
import constant
import utils
import logging


def get_subscriptions():
    subscriptions_data = call_marketplace_api(constant.GET_SUBSCRIPTIONS_ENDPOINT)
    return subscriptions_data


def get_subscriptionid_by_token(token):
    subscription_data = call_marketplace_api(constant.RESOLVE_ENDPOINT, request_method='POST', resolve_token=token, resolve_url=True)
    return subscription_data.json()


def get_subscription(subscription_id):
    subscription_data = call_marketplace_api(constant.GET_SUBSCRIPTION_ENDPOINT(subscription_id))
    return subscription_data


def get_availableplans(subscription_id):
    availableplans = call_marketplace_api(request_url=constant.GET_SUBSCRIPTION_PLANS(subscription_id))
    return availableplans


def activate_subscriptionplan(subscription_id, plan_id):
    request_plan_payload = f"{{'planId':'{plan_id}', 'quantity': 0 }}"
    activateresponse = call_marketplace_api(constant.ACTIVATE_SUBSCRIPTION_ENDPOINT(subscription_id),
    'POST', request_plan_payload)
    return activateresponse


def update_subscriptionplan(subscription_id, plan_id):
    request_plan_payload = F"{{'planId': '{plan_id}'}}"
    updateresponse = call_marketplace_api(constant.UPDATE_SUBSCRIPTION_ENDPOINT(subscription_id), 'PATCH', request_plan_payload)
    
    updateresponseheaders = updateresponse.headers
    updateresponsestatuscode = updateresponse.status_code
    if 'Operation-Location' in updateresponseheaders and updateresponsestatuscode == 202:
        operation_location = updateresponseheaders['Operation-Location']
        subscription_id_returned = re.search('subscriptions/(.*)/operations', operation_location).group(1)
        operation_id = re.search('operations/(.*)\?api-version', operation_location).group(1)
        operation_datetime = updateresponseheaders['Date']
        # store in table storage
        if subscription_id_returned and operation_id:
            # connect to table storgae
            request_payload = {'PartitionKey': subscription_id_returned,
                               'RowKey': operation_id,
                               'updatedtime': operation_datetime,
                               'SubscriptionId': subscription_id_returned,
                               'OperationId': operation_id,
                               'ToPlan': plan_id}
            utils._store_in_azure_table(app_config.ISV_OPS_STORAGE_TABLE_NAME, request_payload)
        else:
            return redirect(url_for(constant.ERROR_PAGE), user=session["user"])
    return updateresponse


def get_sub_operations(subscription_id):
    sub_operations_data = call_marketplace_api(constant.GET_SUBSCRIPTION_OPERATIONS_ENDPOINT(subscription_id))
    sub_operations_data_list = sub_operations_data['operations']
    return sub_operations_data_list


def get_sub_operations_webhook(subscription_id):
    operation_ids_webhook = utils._get_ops_from_azure_table(app_config.WEBHOOK_OPS_STORAGE_TABLE_NAME, subscription_id)
    sub_operations_data_webhook = []
    for op in operation_ids_webhook:
        webhook_op = get_sub_operation(op.PartitionKey, op.RowKey)
        webhook_op['NotificationSource'] = 'WebHook'
        sub_operations_data_webhook.append(webhook_op)
    return sub_operations_data_webhook


def get_sub_operations_isv(subscription_id):
    operation_ids_isv = utils._get_ops_from_azure_table(app_config.ISV_OPS_STORAGE_TABLE_NAME, subscription_id)
    sub_operations_data_isv = []
    for op in operation_ids_isv:
        isv_op = get_sub_operation(op.PartitionKey, op.RowKey)
        isv_op['NotificationSource'] = 'ISVInitiated'
        sub_operations_data_isv.append(isv_op)
    return sub_operations_data_isv


def get_sub_operation(subscription_id, operation):
    sub_operation_data = call_marketplace_api(constant.GET_UPDATE_SUBSCRIPTION_OPERATION_ENDPOINT(subscription_id, operation))
    return sub_operation_data


def update_sub_operation(subscription_id, operation):
    update_operation_response = call_marketplace_api(constant.GET_UPDATE_SUBSCRIPTION_OPERATION_ENDPOINT(subscription_id, operation), 'PATCH')
    return update_operation_response


def get_marketplace_access_token():
    data = {'grant_type': 'client_credentials',
            'client_id': app_config.MARKETPLACEAPI_CLIENT_ID,
            'client_secret': app_config.MARKETPLACEAPI_CLIENT_SECRET, 
            'resource': app_config.MARKETPLACEAPI_RESOURCE}
    
    api_call_headers = {'content-type': 'application/x-www-form-urlencoded'}
    # get token for market place api
    access_token_response = requests.post(constant.MARKETPLACE_TOKEN_ENDPOINT, headers=api_call_headers, data=data).json()
    return access_token_response


def call_marketplace_api(request_url, request_method='GET', request_payload='', resolve_token='', resolve_url=False):
    
    # get token for market place api
    access_token_response = get_marketplace_access_token() 
    global marketplaceheaders
    if not resolve_url:
        
        marketplaceheaders = {'Authorization': 'Bearer ' + access_token_response['access_token'],
                              'Content-Type': 'application/json',
                              'x-ms-requestid': str(uuid.uuid4()),
                              'x-ms-correlationid': str(uuid.uuid4())}
    else:
        global headers
        marketplaceheaders = {'Authorization': 'Bearer ' + access_token_response['access_token'],
                              'x-ms-marketplace-token': resolve_token,
                              'Content-Type': 'application/json',
                              'x-ms-requestid': str(uuid.uuid4()),
                              'x-ms-correlationid': str(uuid.uuid4())}

    if request_method == 'GET':
        logger.info(f"Request: {request_url}")
        logger.info(f"Request: {marketplaceheaders}")
        reponse_data = requests.get(request_url, headers=marketplaceheaders).json()
        logger.info(f"Response: {reponse_data}")
        if not reponse_data:
            logger.info(f"Response: {reponse_data.status_code}")
        return reponse_data
    elif request_method == 'POST':
        reponse_data = requests.post(request_url, headers=marketplaceheaders, data=request_payload)
        return reponse_data
    elif request_method == 'PATCH':
        reponse_data = requests.patch(request_url, headers=marketplaceheaders, data=request_payload)
        return reponse_data
    elif request_method == 'DELETE':
        reponse_data = requests.delete(request_url, headers=marketplaceheaders)
        return reponse_data

