from botocore.exceptions import ClientError

from ec2_instances import get_ec2_resource_name, get_regions, convert_datetime_to_brazil_time
import boto3

def get_volumes(aws_access_key_id, aws_secret_access_key, account_number=None):
    volumes = []

    for region in get_regions():
        ec2_client = boto3.client('ec2', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        try:
            response = ec2_client.describe_volumes(MaxResults=1000)

            if response['Volumes']:
                for volume in response['Volumes']:
                    volumes.append({
                        'Account Name': account_number,  # adicionando nome da conta aqui                            
                        'Name': get_ec2_resource_name(volume['Tags']) if 'Tags' in volume else '-',
                        'Volume ID': volume['VolumeId'],
                        'Type': volume['VolumeType'],
                        'Size': f"{volume['Size']} GiB",
                        'IOPS': volume['Iops'] if 'Iops' in volume else '-',
                        'Throughput': volume['Throughput'] if 'Throughput' in volume else '-',
                        'Snapshot': volume['SnapshotId'],
                        'Created': convert_datetime_to_brazil_time(volume['CreateTime']),
                        'Availability Zone': volume['AvailabilityZone'],
                        'Volume state': volume['State'],
                        'Attached Instances': get_attached_instances(volume['Attachments'], region),
                        'Encryption': 'Encrypted' if volume['Encrypted'] else 'Not encrypted',
	                    'KMS key ID': volume['KmsKeyId'].rsplit('/', 1)[-1] if 'KmsKeyId' in volume else None,
                        'Multi-Attach enabled': volume['MultiAttachEnabled']
                    })
        except ClientError as err:
            if err.response['Error']['Message'] == 'You are not authorized to perform this operation':
                pass

    return volumes

def get_attached_instances(attachments, region):
    attachments_list = []

    for attachment in attachments:
        ec2_client = boto3.client('ec2', region_name=region)

        response = ec2_client.describe_instances(Filters=[
            {
                'Name': 'instance-id',
                'Values': [
                    attachment['InstanceId']
                ]
            },
        ])

    if response.get('Reservations') and response['Reservations'][0].get('Instances'):
        instance_data = response['Reservations'][0]['Instances'][0]
        if instance_data.get('Tags'):
            attachments_list.append(f"{attachment['InstanceId']} ({get_ec2_resource_name(instance_data['Tags'])}): {attachment['Device']} ({attachment['State']})")
        else:
            attachments_list.append(f"{attachment['InstanceId']}: {attachment['Device']} ({attachment['State']})")


    return attachments_list