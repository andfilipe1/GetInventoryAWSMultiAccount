from botocore.exceptions import ClientError
from ec2_instances import get_regions, get_ec2_resource_name, convert_datetime_to_brazil_time
import boto3


def get_nat_gateways(aws_access_key_id, aws_secret_access_key, account_number=None):
    nat_gateways = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_nat_gateways(MaxResults=1000)

            if response['NatGateways']:
                for nat_gateway in response['NatGateways']:
                    elastic_ip_addresses, private_ip_addresses, network_interfaces_ids = get_ip_addresses(nat_gateway['NatGatewayAddresses'])

                    nat_gateways.append({
                        'Account Name': account_number,  # adicionando nome da conta aqui                            
                        'Name': get_ec2_resource_name(nat_gateway['Tags']),
                        'Region': region,
                        'NAT gateway ID': nat_gateway['NatGatewayId'],
                        'Connectivity type': nat_gateway['ConnectivityType'],
                        'State': nat_gateway['State'],
                        'State message': nat_gateway['FailureMessage'] if 'FailureMessage' in nat_gateway else '-',
                        'Elastic IP Address': elastic_ip_addresses,
                        'Private IP address': private_ip_addresses,
                        'Network interface ID': network_interfaces_ids,
                        'VPC': nat_gateway['VpcId'],
                        'Subnet': nat_gateway['SubnetId'],
                        'Created': convert_datetime_to_brazil_time(nat_gateway['CreateTime']),
                        'Deleted': convert_datetime_to_brazil_time(nat_gateway['DeleteTime']) if 'DeleteTime' in nat_gateway else '-'
                    })
        except ClientError as err:
            print(f"Error: {err}")
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return nat_gateways

def get_ip_addresses(nat_gateway_addresses):
    elastic_ip_addresses, private_ip_addresses, network_interfaces_ids = ([] for i in range(3))

    for nat_gateway_address in nat_gateway_addresses:
        elastic_ip_addresses.append(nat_gateway_address['PublicIp'])
        private_ip_addresses.append(nat_gateway_address['PrivateIp'])
        network_interfaces_ids.append(nat_gateway_address['NetworkInterfaceId'])

    return elastic_ip_addresses, private_ip_addresses, network_interfaces_ids