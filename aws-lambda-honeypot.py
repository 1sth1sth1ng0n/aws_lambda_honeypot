from botocore.vendored import requests
import json
import os
import boto3
import sys
from random import randint

#
#   aws lambda function with aws api gateway to issue mdm lock pin
#   to devices defined in a lost/stolen pre-stage scope.
#

jamf_hostname = 'https://jamf-server.com'
secret_manager_arn = "arn:aws:secretsmanager:[ARN]]"
client = boto3.client("secretsmanager")
response = client.get_secret_value(SecretId = (secret_manager_arn))
secret_dict = json.loads(response["SecretString"])
user = secret_dict["username"]
pd = secret_dict["password"]
scope_id = '16' # define jamf prestage scope id
debug = True # safety trigger

def lambda_handler(event, context):

    """ jamf_id from jamf pro webhook payload body """
    body = json.loads(event['body'])
    jamf_id = body['event']['groupAddedDevicesIds']

    """ check we received an id list item, this may be a 'groupRemovedDevicesIds' call and have an empty list """
    if len(jamf_id) == 0:
            print('did not receive a jamf_id....exiting')
            sys.exit(1)

    else:
        
        """ we assume that only one asset [0] is added to the honey pot prestage at a time - 
        we could iterate the list and make multiple actions if required """
        first_jamf_id = jamf_id[0]
        print(f'received jamf_id: {first_jamf_id}')

        """ an empty smart group criteria would include all devices - validate we are targeting 
        the correct device.
        use jamf_id to confirm device serial number and check prestage scope membership """
        api_token = get_token()
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + api_token}
        serial_number_endpoint = f'{jamf_hostname}/api/v1/computers-inventory/{first_jamf_id}?section=HARDWARE'
        sn_response = requests.get(serial_number_endpoint, headers=headers)

        if sn_response.status_code == 200:
            """ create dict from json response """
            sn_data = json.loads(sn_response.content.decode('utf-8'))
            serial_number = sn_data['hardware']['serialNumber']
            print(f'found s/n: {serial_number} using submitted jamf_id {first_jamf_id}')

            prestage_scope = f'{jamf_hostname}/api/v2/computer-prestages/{scope_id}/scope'
            response = requests.get(prestage_scope, headers=headers)

            if response.status_code == 200:
                """ create dict from json response """
                scope_data = json.loads(response.content.decode('utf-8'))
                new_scope_data = scope_data['assignments']

                # create a list we can iterate more easily
                serials = []

                for serial in new_scope_data:
                    serials.append(serial['serialNumber'])

                if serial_number in serials:
                    print(f'{serial_number} is in the defined jamf pre-stage group...')

                    if debug == False:
                        """ creates random 6 digit int for lock pin"""
                        def random_int(n):
                            start = 10**(n-1)
                            stop = (10**n)-1
                            return randint(start, stop)
                        
                        mdm_lock_pin = random_int(6)

                        print(f'issuing mdm lock to device: {first_jamf_id} {serial_number}. pin code = {mdm_lock_pin}')
                        mdm_command = f'{jamf_hostname}/JSSResource/computercommands/command/DeviceLock/passcode/{mdm_lock_pin}/id/{jamf_id}'
                        mdm_command_response = requests.get(mdm_command, headers=headers)

                        if mdm_command_response.status_code == 200:
                            """ create dict from json response"""
                            command_data = json.loads(mdm_command_response.content.decode('utf-8')) 
                            print(f'{command_data}]')

                            slack_webhook = "https://hooks.slack.com/services/[WEBHOOK]"
                            slack_payload = f'{"text":"[LOST-OR-STOLEN-DEVICE] *{serial_number}* was just MDM locked with Pin Code: {mdm_lock_pin}. Go check it out!"}'
                            post_slack(slack_payload, slack_webhook)
                        
                        else:
                            print(f'error issuing mdm lock to device: {first_jamf_id} {serial_number}.')

                    else:
                        print(f'debug is {debug}....no command issued.')

                else:
                    print(f'{serial_number} is not in the defined jamf pre-stage group.')

            else:
                print('...error:',sn_response.content.decode('utf-8'))


        drop_token(api_token)

""" request jamf api token """
def get_token():

    token_url = f'{jamf_hostname}/api/v1/auth/token'
    headers = {'Accept': 'application/json', }
    response = requests.post(url=token_url, headers=headers, auth=(user, pd))
    response_json = response.json()
    print(f'...api token obtained from {jamf_hostname}')
    return response_json['token']

""" invalidate jamf api token """
def drop_token(api_token):

    token_drop_url = f'{jamf_hostname}/api/v1/auth/invalidate-token'
    headers = {'Accept': '*/*', 'Authorization': 'Bearer ' + api_token}
    response = requests.post(url=token_drop_url, headers=headers)

    if response.status_code == 204:
        print('...api token invalidated.')

    else:
        print('...error invalidating api token.')

""" private slack channel alert """
def post_slack(payload, webhook):

    return requests.post(webhook, json.dumps(payload))