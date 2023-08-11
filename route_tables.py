from botocore.exceptions import ClientError
from ec2_instances import get_regions, get_ec2_resource_name
import boto3

def get_route_tables(aws_access_key_id, aws_secret_access_key,account_number):
    route_tables = []
    subnets_associations = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_route_tables(MaxResults=100)

            for route_table in response['RouteTables']:
                route_table_associations = route_table['Associations']

                for subnet_association in get_subnets_associations(route_table_associations, region):
                    subnets_associations.append(subnet_association)

                route_tables.append({
                    'Account Name': account_number,                          
                    'Name': get_ec2_resource_name(route_table['Tags']),
                    'Region': region,
                    'Route table ID': route_table['RouteTableId'],
                    'Explicit subnet associations': set_explicit_subnet_associations(route_table_associations),
                    'Main': set_main_route_table(route_table_associations),
                    'VPC': route_table['VpcId'],
                    'Owner ID': route_table['OwnerId']
                })

        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return route_tables, subnets_associations

def get_subnets_associations(associations, region):
    subnets_associations = []

    for association in associations:
        if 'SubnetId' in association:
            subnets_associations.append({
                'SubnetId': association['SubnetId'],
                'RouteTableId': association['RouteTableId']
            })
        else:
            subnets_associations.append({
                'Region': region,
                'RouteTableId': association['RouteTableId']
            })

    return subnets_associations


def set_main_route_table(associations):
    for association in associations:
        if association['Main']:
            return 'Yes'

    return 'No'

def set_explicit_subnet_associations(associations):
    count_associations = 0
    should_return_number_of_associations = False

    for association in associations:
        if 'SubnetId' in association:
            count_associations = count_associations + 1
            should_return_number_of_associations = True

    if should_return_number_of_associations:
        return f'{count_associations} subnets'

    return '-'