from botocore.exceptions import ClientError

from ec2_instances import get_regions, get_ec2_resource_name
import boto3

def get_vpcs(route_tables, network_acls, aws_access_key_id, aws_secret_access_key, account_number=None):
    vpcs = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_vpcs(MaxResults=100)

            for vpc in response['Vpcs']:
                vpc_id = vpc['VpcId']

                vpcs.append({
                    'Account Name': account_number,   
                    'Name': get_ec2_resource_name(vpc['Tags']) if 'Tags' in vpc else '-',
                    'Region': region,
                    'VPC ID': vpc_id,
                    'State': vpc['State'],
                    'IPv4 CIDR': vpc['CidrBlock'],
                    'IPv6 CIDR': get_ipv6_cidr(vpc),
                    'DHCP option set': vpc['DhcpOptionsId'],
                    'Main route table': get_main_route_table(route_tables, vpc_id),
                    'Main network ACL': get_main_network_acl(network_acls, vpc_id),
                    'Tenancy': vpc['InstanceTenancy'],
                    'Default VPC': 'Yes' if vpc['IsDefault'] else 'No',
                    'Owner ID': vpc['OwnerId']
                })
        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return vpcs

def get_main_network_acl(network_acls, vpc_id):
    for network_acl in network_acls:
        if vpc_id == network_acl['VPC ID']:
            return network_acl['Network ACL ID']

    return '-'

def get_main_route_table(route_tables, vpc_id):
    for route_table in route_tables:
        if vpc_id == route_table['VPC'] and route_table['Main'] == 'Yes':
            return route_table['Route table ID']

def get_ipv6_cidr(vpc):
    ipv6_cidr_list = []

    if 'Ipv6CidrBlockAssociationSet' in vpc:
        for cidr_block_association_set in vpc['Ipv6CidrBlockAssociationSet']:
            ipv6_cidr_list.append(cidr_block_association_set['Ipv6CidrBlock'])

        return ipv6_cidr_list
    else:
        return '-'