import boto3
import pytz
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def get_instances(aws_access_key_id, aws_secret_access_key, account_number=None):
    instances = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_instances(MaxResults=500)

            if response['Reservations']:
                for instances_list in response['Reservations']:
                    for instance in instances_list['Instances']:
                        instances.append({
                            'Account Name': account_number,                             
                            'Name': get_ec2_resource_name(instance['Tags']) if 'Tags' in instance else '-',
                            'Instance ID': instance['InstanceId'],
                            'Instance state': instance['State']['Name'],
                            'Instance type': instance['InstanceType'],
                            # Fazer teste com instância parada
                            'Status check': get_instance_status_check(region, instance['InstanceId'], aws_access_key_id, aws_secret_access_key),
                            'Availability Zone': instance['Placement']['AvailabilityZone'],
                            'Private IP': instance['PrivateIpAddress'],
                            'Public DNS': instance['PublicDnsName'],
                            'Public IP': instance['PublicIpAddress'] if 'PublicIpAddress' in instance else '-',
                            'Monitoring': instance['Monitoring']['State'],
                            'Security group name': get_security_groups_names(instance['NetworkInterfaces']),
                            'Key name': instance['KeyName'] if 'KeyName' in instance else '-',
                            'Launch time': convert_datetime_to_brazil_time(instance['LaunchTime']),
                        })
        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return instances

def convert_datetime_to_brazil_time(date):
    tz = pytz.timezone('Brazil/East')

    return date.astimezone(tz).strftime('%Y/%m/%d %H:%M')

def get_security_groups_names(network_interfaces):
    sg = []

    for network_interface in network_interfaces:
        for group in network_interface['Groups']:
            if group['GroupName'] in sg:
                continue
            else:
                sg.append(group['GroupName'])

    return sg

def get_instance_status_check(region, instance_id, aws_access_key_id, aws_secret_access_key):
    status = {'InstanceStatus': 'None', 'SystemStatus': 'None'}

    ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    response = ec2_client.describe_instance_status(InstanceIds=[instance_id])

    for instance_status in response['InstanceStatuses']:
        for detail in instance_status['InstanceStatus']['Details']:
            if detail['Name'] == 'reachability':
                status['InstanceStatus'] = detail['Status']

        for detail in instance_status['SystemStatus']['Details']:
            if detail['Name'] == 'reachability':
                status['SystemStatus'] = detail['Status']

    status_check = format_instance_status_check(status)

    return status_check

def format_instance_status_check(status):
    if status['InstanceStatus'] == 'passed' and status['SystemStatus'] == 'passed':
        return '2/2 checks passed'
    elif status['InstanceStatus'] != 'passed' and status['SystemStatus'] == 'passed':
        return f"1/2 checks passed InstanceStatus has status: {status['InstanceStatus']}"
    elif status['SystemStatus'] != 'passed' and status['InstanceStatus'] == 'passed':
        return f"1/2 checks passed SystemStatus has status: {status['SystemStatus']}"
    else:
        return f"0/2 checks passed SystemStatus has status: {status['SystemStatus']}, InstanceStatus has status: {status['InstanceStatus']} "

def get_ec2_resource_name(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']

    return '-'

def get_regions():
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    return regions
