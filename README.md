# Introduction
SG Sentry function:

The bot automatically reverts changes to your VPC Security Group and sends an email notification containing information about those changes.


# Workflow
1. a new inbound rule is added to the SG
2. a CloudWatch event triggers the Lambda function
3. the script reverts the new Security Group ingress rule
4. an email notification is sent via SNS with information about the change, who made it and confirm the change was reverted.

# Pre-requisite
- CloudTrail has to be enabled in the AWS Region where the solution is deployed
- VPC with custom Security Groups
- IAM role for the Lambda with EC2FullAccess permissions (more restrictive permission can be applied).
- os, json, boto3, botocore, logging modules installed

# Instructions
1. Make sure a Trail in ***CloudTrail*** is created to enable logs in the region where the bot will operate.
This allows the Lambda function to use the event log to parse information about the API call.

2. ***Create the VPC*** and ***create a security*** group with the desired inbound rules.
The inbound rules created before deploying the Lambda function will be considered the default state.
From the deployment of the Lambda function, any new inbound rule will be deleted.

3. ***Create the IAM role*** for the Lamba function:
Attach the EC2FullAccess policy type (we will use full permission for the testing but it’s best practice to apply the principle of least privilege).
name it and create it.
Make sure that this role has the following policies attached:

- AWSLambdaBasicExecutionRole

- AWSLambdaSNSPublishPolicyExecutionRole

    And relative permission to access EC2

4. ***Create the Lambda*** Function:
add the code provided
update the global variables (global variables can be found at the beginning of the script. 
create the following environment variables: 

SECURITY_GROUP_ID : insert the security group ID

sns_topic_arn : insert the SNS topic ARN

5. ***Add CloudWatch event*** as trigger:
From the function overview, select “add trigger”	
Select EventBridge as a source
Select “create a new rule” and name it
Select "event pattern" as rule type,  EC2 from the first drop-down menu,  AWS API call via CloudTrail from the second drop-down menu
Under Detail, thick the "operation" box and select the following operation:

- AuthorizeSecurityGroupIngress

    Add the trigger and save changes

6. ***Create the SNS Topic***:
Create a new topic, Standard type
Name it
Any other setting can be left as default
Create now a Subscription:
Under “Protocol” select Email and under “endpoint” insert the email address
Any other setting can be left as default
Create the subscription. 
Confirm subscription by clicking on the link sent to the email address used in the subscription

7. Add ***Amazon SNS*** as destination:
From the function overview select “add destination”
Under “destination” simply select the topic created in step 5. If the topic doesn’t appear in the drop-down menu, please click the refresh button next to it.

8. ***Test*** the function:
Add an inbound rule to the security group. Adding this rule creates an EC2 AuthorizeSecurityGroupIngress service event, which trigger the Lambda function. 
After refreshing a couple of times, the new inbound rule should disappear and you should receive an email with the relative information.
