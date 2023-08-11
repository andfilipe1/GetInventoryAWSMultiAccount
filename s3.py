import boto3
import botocore
from botocore.exceptions import ClientError
from ec2_instances import convert_datetime_to_brazil_time


def get_buckets(aws_access_key_id, aws_secret_access_key, account_number):
    client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    s3 = boto3.resource('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    buckets_data = {'Buckets': [], 'LifecycleRules': []}


    for bucket in s3.buckets.all():
        bucket_versioning = get_bucket_versioning(client,bucket.name)
        bucket_encryption = get_bucket_encryption(client, bucket.name)
        bucket_lifecycle = get_buckets_lifecycle(client, bucket.name)

        if bucket_lifecycle is not None:
            for rule in bucket_lifecycle:
                buckets_data['LifecycleRules'].append(rule)

        buckets_data['Buckets'].append({
            'Account Name': account_number,  # adicionando nome da conta aqui                            
            'Name': bucket.name,
            'AWS Region': get_bucket_region(client, bucket.name),
            'Access': get_bucket_access(client, bucket.name),
            # This date can change when making changes to your bucket, such as editing its bucket policy.
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Bucket.creation_date
            'Creation date': convert_datetime_to_brazil_time(bucket.creation_date),
            'Versioning': bucket_versioning['Status'],
            'MFA Delete': bucket_versioning['MFADelete'],
            'Encryption': bucket_encryption['Status'],
            'Key type': bucket_encryption['KeyType'],
            'Key': bucket_encryption['Key'],
        })

    return buckets_data

def get_bucket_encryption(client,bucket_name):
    bucket_encryption = {}

    try:
        response = client.get_bucket_encryption(Bucket=bucket_name)

        bucket_encryption['Status'] = 'Enabled'
        bucket_encryption['KeyType'] = response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        bucket_encryption['Key'] = 'Enabled' if response['ServerSideEncryptionConfiguration']['Rules'][0]['BucketKeyEnabled'] is True else 'Disabled'

        return bucket_encryption
    except ClientError as err:
        if err.response['Error']['Message'] == 'The server side encryption configuration was not found':
            bucket_encryption['Status'] = 'Disabled'
            bucket_encryption['KeyType'] = ''
            bucket_encryption['Key'] = ''

            return bucket_encryption

        print(err.response)

def get_bucket_versioning(client, bucket_name):
    bucket_versioning = {}

    response = client.get_bucket_versioning(Bucket=bucket_name)

    if 'Status' in response:
        bucket_versioning['Status'] = response['Status']
    else:
        bucket_versioning['Status'] = 'Disabled'

    if 'MFADelete' in response:
        bucket_versioning['MFADelete'] = response['MFADelete']
    else:
        bucket_versioning['MFADelete'] = 'Disabled'

    return bucket_versioning

def get_buckets_lifecycle(client, bucket_name):
    try:
        rules = []

        response = client.get_bucket_lifecycle(Bucket=bucket_name)

        for rule in response['Rules']:
            rules.append({
                'Bucket name': bucket_name,
                'Lifecycle rule name': rule['ID'],
                'Status': rule['Status'],
                'Current version actions': format_lifecycle_current_version(rule)
            })

        return rules
    except ClientError as err:
        if err.response['Error']['Message'] == 'The lifecycle configuration does not exist':
            pass
        else:
            print(err.response['Error'])

def format_lifecycle_current_version(rule):
    if 'Transition' in rule:
        current_version_actions = set_version_action(rule['Transition']['StorageClass'])

        if 'Expiration' in rule:
            current_version_actions = ', '.join((current_version_actions, 'then expires'))

        return current_version_actions

    if 'Expiration' in rule:
        return 'Expires'

    return 'None'

def set_version_action(storage_class):
    if storage_class == 'DEEP_ARCHIVE':
        return 'Transition to Glacier Deep Archive'
    elif storage_class == 'GLACIER':
        return 'Transition to Glacier'
    elif storage_class == 'STANDARD_IA':
        return 'Transition to Standard-Infrequent Access'
    elif storage_class == 'ONEZONE_IA':
        return 'Transition to One-Zone Infrequent Access'
    elif storage_class == 'INTELLIGENT_TIERING':
        return 'Transition to Intelligent-Tiering'
    elif storage_class == 'GLACIER_IR':
        return 'Transition to Glacier Instant Retrieval'

def get_bucket_region(client, bucket_name):
    response = client.get_bucket_location(Bucket=bucket_name)

    # Buckets in Region us-east-1 have a LocationConstraint of null
    if response['LocationConstraint'] is None:
        return 'us-east-1'

    return response['LocationConstraint']

def get_bucket_access(client, bucket_name):
    is_public = False

    try:
        response = client.get_public_access_block(Bucket=bucket_name)
    except botocore.exceptions.ClientError as err:
        if err.response['Error']['Message'] == 'The public access block configuration was not found':
            return 'Bucket has no public access configuration'

    if response['PublicAccessBlockConfiguration']['BlockPublicAcls'] is False and response['PublicAccessBlockConfiguration']['BlockPublicPolicy'] is False:
        is_public = True

    try:
        response = client.get_bucket_policy_status(Bucket=bucket_name)

        if response['PolicyStatus']['IsPublic']:
            is_public = True
    except ClientError as err:
        if err.response['Error']['Message'] == 'The bucket policy does not exist':
            pass
        else:
            print(err.response['Error'])

    response = client.get_bucket_acl(Bucket=bucket_name)

    for grantee in response['Grants']:
        if 'Type' in grantee and 'URI' in grantee:
            if grantee['Type'] == 'Group' and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' or grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                is_public = True

    if is_public is False:
        return 'Bucket and objects not public'

    return 'Bucket has public access'