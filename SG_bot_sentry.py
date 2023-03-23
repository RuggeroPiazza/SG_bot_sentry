"""
   This Python script automatically removes new security groups ingress rules.
   Amazon EventBridge triggers this Lambda function when AWS CloudTrail detects
   a AuthorizeSecurityGroupIngress API event initiated by an IAM user. Next, this Lambda Function
   delete the new entry and send a notification to the admin to report the succesful or failed deletion.
   Outputs get logged and status codes are returned. 
"""

import os
import json
import logging
import boto3
import botocore


# logging
log = logging.getLogger()
log.setLevel(logging.INFO)

# global variables
SECURITY_GROUP_ID = os.environ.get('security_group_id')
SNS_TOPIC_ARN = os.environ['sns_topic_arn']
if SECURITY_GROUP_ID is None:
    raise Exception("Security group ID not found, make sure the environment variable is been set correctly")

# instantiate boto3 client
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')


def lambda_handler(event, context):
    event_name = event.get('detail', {}).get('eventName')
    security_group_id = event.get('detail', {}).get('requestParameters', {}).get('groupId')

    if security_group_id == SECURITY_GROUP_ID and event_name == "AuthorizeSecurityGroupIngress":
        event_detail = event['detail']
        if revoke_security_group(event_detail):
            log.info("RevokeSecurityGroupIngress: successful")
            if send_notifications(event_detail):
                log.info("SNS publish: successful")
                return {
                    'statusCode': 200,
                    'body': json.dumps({'message': "Successful requests"})
                }
            log.info("SNS publish: an error occurred")
            return {
                'statusCode': 206,
                'body': json.dumps({'error': "An error occurred in the SNS publish request."})
            }
        log.info("RevokeSecurityGroupIngress: an error occurred")
        if not send_notifications(event_detail, False):
            return {
                'statusCode': 500,
                'body': json.dumps({'error': "An error occurred, all requests failed."})
            }
        return {
            'statusCode': 206,
            'body': json.dumps({'error': "An error occurred in the RevokeSecurityGroupIngress request."})
        }
    

def revoke_security_group(event_detail):
    """
    Get the correct input structure to pass to the revoke_security_group_ingress
    method. Return true if succesfull, log the error and return False if fails.
    """
    request_parameters = event_detail['requestParameters']
    # Build the normalized IP permission JSON structure.
    ip_permissions = normalize_parameter_names(request_parameters['ipPermissions']['items'])
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=request_parameters['groupId'],
            IpPermissions=ip_permissions
        )
        return True
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error: {error}")
        return False


def normalize_parameter_names(ip_items):
    """
    Build the permission items list in the correct form to be accepted by the 
    revoke_security_group_ingress method. For more details about this input, please 
    check the method's documentation.
    """
    # Start building the permissions items list.
    new_ip_items = []

    # First, build the basic parameter list.
    for ip_item in ip_items:
        new_ip_item = {
            "IpProtocol": ip_item['ipProtocol'],
            "FromPort": ip_item['fromPort'],
            "ToPort": ip_item['toPort']
        }
        # CidrIp or CidrIpv6 (IPv4 or IPv6)?
        version = 'v6' if ip_item.get('ipv6Ranges') else ''
        ipv_range_list_name, ipv_range_list_name_capitalized = f'ip{version}Ranges', f'Ip{version}Ranges'
        ipv_address_value, ipv_address_value_capitalized = f'cidrIp{version}', f'CidrIp{version}'

        ip_ranges = []

        # Next, build the IP permission list.
        for item in ip_item[ipv_range_list_name]['items']:
            ip_ranges.append(
                {ipv_address_value_capitalized: item[ipv_address_value]}
            )

        new_ip_item[ipv_range_list_name_capitalized] = ip_ranges

        new_ip_items.append(new_ip_item)

    return new_ip_items


def send_notifications(event_detail, success=True):
    """
    Parse information about the user and the security group ID, creates a message
    accordingly and sends a notification via AWS SNS to the topic saved in the 
    environment variable.
    Returns True if succesful, if an error occurs, log the error and returns False.
    """
    request_parameters = event_detail['requestParameters']
    message = "AUTO-MITIGATED: new security group ingress rules successfully deleted.\n"
    subject = "Auto-Mitigation successful"
    if not success:
        message = "A new security group rule is being created but the RevokeSecurityGroupIngress request has failed.\n"
        subject = "Warning: Auto-Mitigation unsuccessful"

    message += (
            f"group_id: {request_parameters['groupId']}\n" 
            f"user_name: {event_detail['userIdentity']['arn']}\n"
            )
    try:
        sns_client.publish(TargetArn=SNS_TOPIC_ARN, Message=message, Subject=subject)
        return True
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned eror: {error}")
        return False
