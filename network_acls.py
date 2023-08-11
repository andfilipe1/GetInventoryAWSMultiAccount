from botocore.exceptions import ClientError
from ec2_instances import get_regions, get_ec2_resource_name
import boto3

def get_network_acls(aws_access_key_id, aws_secret_access_key,account_number):
    network_acls = []
    subnets_network_acls = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key )

        try:
            response = ec2_client.describe_network_acls(MaxResults=100)

            for network_acl in response['NetworkAcls']:
                rules_counter = get_rules_count(network_acl['Entries'])

                network_acl_associations = network_acl['Associations']

                for subnet_network_acl in get_subnets_network_acls(network_acl_associations):
                    subnets_network_acls.append(subnet_network_acl)

                network_acls.append({
                    'Account Name': account_number,                            
                    'Name': get_ec2_resource_name(network_acl['Tags']),
                    'Region': region,
                    'Network ACL ID': network_acl['NetworkAclId'],
                    'Associated with': f"{len(network_acl_associations)} Subnets",
                    'Default': 'Yes' if network_acl['IsDefault'] else 'No',
                    'VPC ID': network_acl['VpcId'],
                    'Inbound rules count': f'{rules_counter["Inbound"]} Inbound rules',
                    'Outbound rules count': f'{rules_counter["Outbound"]} Outbound rules',
                    'Owner': network_acl['OwnerId']
                })
        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return network_acls, subnets_network_acls

def get_subnets_network_acls(associations):
    subnets_network_acls = []

    for association in associations:
        subnets_network_acls.append({
            'SubnetId': association['SubnetId'],
            'NetworkAclId': association['NetworkAclId']
        })

    return subnets_network_acls

def get_rules_count(rules):
    rules_counter = {'Inbound': 0, 'Outbound': 0}

    for rule in rules:
        if rule['Egress']:
            rules_counter['Outbound'] = rules_counter['Outbound'] + 1
        else:
            rules_counter['Inbound'] = rules_counter['Inbound'] + 1

    return rules_counter
