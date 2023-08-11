import logging
from ec2_instances import get_instances
from ec2_volumes import get_volumes
from s3 import get_buckets
from security_groups import get_security_groups
from vpcs import get_vpcs
from route_tables import get_route_tables
from network_acls import get_network_acls
from subnets import get_subnets
from nat_gateways import get_nat_gateways
from transit_gateways import get_transit_gateways
from excel import generate_excel
from accounts_credentials import accounts
from botocore.exceptions import ClientError

import logging

logging.basicConfig(level=logging.INFO, handlers=[logging.FileHandler("aws_inventory.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

def main(aws_access_key_id=None, aws_secret_access_key=None, account_number=None):  
    logger.info('Getting inventory from AWS...')


    resources = {}
    s3_data = get_buckets(aws_access_key_id, aws_secret_access_key,account_number)
    security_groups_data = get_security_groups(aws_access_key_id, aws_secret_access_key,account_number)
    route_tables, route_tables_subnets_associations = get_route_tables(aws_access_key_id, aws_secret_access_key,account_number)
    network_acls, subnets_network_acls_associations = get_network_acls(aws_access_key_id, aws_secret_access_key,account_number)

    resources['Instances'] = get_instances(aws_access_key_id, aws_secret_access_key,account_number)  
    resources['Volumes'] = get_volumes(aws_access_key_id, aws_secret_access_key,account_number)  
    resources['Buckets'] = s3_data['Buckets']
    resources['Buckets Lifecycle Rules'] = s3_data['LifecycleRules']
    resources['Security Groups'] = security_groups_data['SecurityGroups']
    resources['Security Groups Rules'] = security_groups_data['SecurityGroupsRules']
    resources['Vpcs'] = get_vpcs(route_tables, network_acls, route_tables_subnets_associations, subnets_network_acls_associations, aws_access_key_id, aws_secret_access_key, account_number)
    resources['Route tables'] = route_tables
    resources['Network ACLS'] = network_acls
    resources['Subnets'] = get_subnets(route_tables_subnets_associations, subnets_network_acls_associations, aws_access_key_id, aws_secret_access_key, account_number)
    resources['NAT Gateways'] = get_nat_gateways(aws_access_key_id, aws_secret_access_key, account_number)
    resources['Transit Gateways'] = get_transit_gateways(aws_access_key_id, aws_secret_access_key, account_number)

    return resources

if __name__ == '__main__':
    all_data = {
        'Instances': [],
        'Volumes': [],
        'Buckets': [],
        'Buckets Lifecycle Rules': [],
        'Security Groups': [],
        'Security Groups Rules': [],
        'Vpcs': [],
        'Route tables': [],
        'Network ACLS': [],
        'Subnets': [],
        'NAT Gateways': [],
        'Transit Gateways': [], 
    }
    
    for account_number, credentials in accounts.items():
        logger.info(f"Fetching inventory for {account_number} ...")
        try:
            resources = main(credentials['aws_access_key_id'], credentials['aws_secret_access_key'], account_number)
        
            for resource_name, resource_data in resources.items():
                all_data[resource_name].extend(resource_data)

            for resource_name, resource_data in all_data.items():
                logger.info(f"{resource_name}: {len(resource_data)} items")
        except ClientError as e:
            if e.response['Error']['Code'] == 'SignatureDoesNotMatch':
                logger.error(f"Authentication error for account {account_number}. Skipping...")
            else:
                logger.error(f"Unexpected error for account {account_number}: {e}")
          
    generate_excel(all_data)
