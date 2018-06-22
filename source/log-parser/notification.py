from os import getenv
import json
import boto3

SNS_TOPIC_ARN = getenv('SNS_TOPIC_ARN')
SUBJECT = 'Outstanding requesters list updated'

sns = boto3.client('sns')

def publish(data):
    if not SNS_TOPIC_ARN:
        return
    message = json.dumps(data)
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=SUBJECT, Message=message)
