from botocore.exceptions import ClientError
from ec2_instances import get_regions, get_ec2_resource_name
import boto3

def get_transit_gateways(aws_access_key_id, aws_secret_access_key, account_number=None):
    transit_gateways = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_transit_gateways(MaxResults=1000)

            if response['TransitGateways']:
                for transit_gateway in response['TransitGateways']:
                    transit_gateways.append({
                        'Account Name': account_number,                                
                        'Name': get_ec2_resource_name(transit_gateway['Tags']),
                        'Region': region,
                        'Transit gateway ID': transit_gateway['TransitGatewayId'],
                        'Description': transit_gateway.get('Description', 'N/A'),
                        'Owner ID': transit_gateway['OwnerId'],
                        'State': transit_gateway['State'],
                        'Amazon ASN': transit_gateway['Options']['AmazonSideAsn'],
                        'DNS support': transit_gateway['Options']['DnsSupport'],
                        'VPN ECMP support': transit_gateway['Options']['VpnEcmpSupport'],
                        'Auto accept shared attachments': transit_gateway['Options']['AutoAcceptSharedAttachments'],
                        'Default association route table': transit_gateway['Options']['DefaultRouteTableAssociation'],
                        'Multicast support': transit_gateway['Options']['MulticastSupport'],
                        'Association route table ID': transit_gateway['Options']['AssociationDefaultRouteTableId'],
                        'Default propagation route table': transit_gateway['Options']['DefaultRouteTablePropagation'],
                        'Propagation route table ID': transit_gateway['Options']['PropagationDefaultRouteTableId'],
                        'Transit gateway CIDR blocks': transit_gateway['Options']['TransitGatewayCidrBlocks'] if 'TransitGatewayCidrBlocks' in transit_gateway['Options'] else '-'
                    })
        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return transit_gateways