from botocore.exceptions import ClientError
from ec2_instances import get_regions, get_ec2_resource_name
import boto3

def get_subnets(route_tables_subnets_associations, subnets_network_acls_associations, aws_access_key_id, aws_secret_access_key, account_number=None):
    subnets = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_subnets(MaxResults=300)

            for subnet in response['Subnets']:
                subnet_id = subnet['SubnetId']

                subnets.append({
                    'Account Name': account_number, 
                    'Name': get_ec2_resource_name(subnet['Tags']) if 'Tags' in subnet else '-',
                    'Region': region,
                    'Subnet ID': subnet_id,
                    'State': subnet['State'],
                    'VPC': subnet['VpcId'],
                    'IPv4 CIDR': subnet['CidrBlock'],
                    'IPv6 CIDR': subnet['Ipv6CidrBlockAssociationSet']['Ipv6CidrBlock'][0] if len(subnet['Ipv6CidrBlockAssociationSet']) >= 1 else '-',
                    'Available IPv4 addresses': subnet['AvailableIpAddressCount'],
                    'Availability Zone': subnet['AvailabilityZone'],
                    'Availability Zone ID': subnet['AvailabilityZoneId'],
                    'Route table': set_subnet_route_table(route_tables_subnets_associations, region, subnet_id),
                    'Network ACL': set_subnet_network_acl(subnets_network_acls_associations, subnet_id),
                    'Default subnet': 'Yes' if subnet['DefaultForAz'] else 'No',
                    'Auto-assign public IPv4 address': 'Yes' if subnet['MapPublicIpOnLaunch'] else 'No',
                    'Auto-assign customer-owned IPv4 address': 'Yes' if 'MapCustomerOwnedIpOnLaunch' in subnet and subnet['MapCustomerOwnedIpOnLaunch'] else 'No',
                    'Auto-assign IPv6 address': 'Yes' if subnet['AssignIpv6AddressOnCreation'] else 'No',
                    'Owner ID': subnet['OwnerId']
                })
        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return subnets

def set_subnet_network_acl(subnets_network_acls_associations, subnet_id):
    for subnet_network_acl_association in subnets_network_acls_associations:
        if subnet_network_acl_association['SubnetId'] == subnet_id:
            return subnet_network_acl_association['NetworkAclId']

    return '-'

def set_subnet_route_table(route_tables_subnets_associations, region, subnet_id):
    for route_table_subnet_association in route_tables_subnets_associations:
        if 'SubnetId' in route_table_subnet_association:
            if route_table_subnet_association['SubnetId'] == subnet_id:
                return route_table_subnet_association['RouteTableId']

    for route_table_subnet_association in route_tables_subnets_associations:
        if 'Region' in route_table_subnet_association:
            if route_table_subnet_association['Region'] == region:
                return route_table_subnet_association['RouteTableId']

    return '-'