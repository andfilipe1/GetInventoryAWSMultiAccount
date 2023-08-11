from botocore.exceptions import ClientError
from ec2_instances import get_regions, get_ec2_resource_name
import boto3

def get_security_groups(aws_access_key_id, aws_secret_access_key,account_number):
    security_groups = {'SecurityGroups': [], 'SecurityGroupsRules': []}

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_security_groups(MaxResults=1000)

            if response['SecurityGroups']:
                for security_group in response['SecurityGroups']:
                    security_group_rules = get_security_group_rules(security_group['GroupId'], ec2_client)

                    security_groups['SecurityGroups'].append({
                        'Account Name': account_number,  # adicionando nome da conta aqui                            
                        'Name': get_ec2_resource_name(security_group['Tags']) if 'Tags' in security_group else '-',
                        'Region': region,
                        'Security group ID': security_group['GroupId'],
                        'Security group name': security_group['GroupName'],
                        'VPC ID': security_group['VpcId'],
                        'Description': security_group['Description'],
                        'Owner': security_group['OwnerId'],
                    })

                    for security_group_rule in security_group_rules:
                        security_groups['SecurityGroupsRules'].append({
                            'Rule name': security_group_rule['Name'],
                            'Security Group Id': security_group['GroupId'],
                            'Owner': security_group['OwnerId'],
                            'Region': region,
                            'Type': security_group_rule['Type'],
                            'Destination': security_group_rule['Destination'],
                            'Security group rule ID': security_group_rule['SecurityGroupRuleID'],
                            'Protocol': security_group_rule['Protocol'],
                            'Port range': security_group_rule['PortRange'],
                            'Source': security_group_rule['Source'],
                            'Rule Description': security_group_rule['Description']
                        })

        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return security_groups

def get_security_group_rules(security_group_id, ec2_client):
    rules = []

    response = ec2_client.describe_security_group_rules(Filters=[
        {
            'Name': 'group-id',
            'Values': [
                security_group_id
            ]
        },
    ])

    for rule in response['SecurityGroupRules']:
        if rule['IsEgress']:
            rules.append({
                'Name': get_ec2_resource_name(rule['Tags']),
                'Type': 'Outbound',
                'Destination': rule['CidrIpv4'] if 'CidrIpv4' in rule else '-',
                'SecurityGroupRuleID': rule['SecurityGroupRuleId'],
                'Protocol': 'All' if rule['IpProtocol'] == '-1' else rule['IpProtocol'],
                'PortRange': format_port_range(rule['FromPort'], rule['ToPort']),
                'Source': '',
                'Description': rule['Description'] if 'Description' in rule else '-'
            })
        else:
            rules.append({
                'Name': get_ec2_resource_name(rule['Tags']),
                'Type': 'Inbound',
                'Destination': '-',
                'SecurityGroupRuleID': rule['SecurityGroupRuleId'],
                'Protocol': 'All' if rule['IpProtocol'] == '-1' else rule['IpProtocol'],
                'PortRange': format_port_range(rule['FromPort'], rule['ToPort']),
                'Source': rule['PrefixListId'] if 'PrefixListId' in rule else rule['ReferencedGroupInfo'][
                    'GroupId'] if 'ReferencedGroupInfo' in rule else '-',
                'Description': rule['Description'] if 'Description' in rule else '-'
            })

    return rules

def format_port_range(from_port, to_port):
    if from_port == -1 and to_port == -1:
        return 'All'
    elif from_port == to_port:
        return f'{from_port}'
    else:
        return f'{from_port} - {to_port}'
