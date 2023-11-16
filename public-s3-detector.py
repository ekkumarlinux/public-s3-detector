import boto3
from botocore.exceptions import ClientError

def check_public_access():
    # Initialize the S3 client
    s3_client = boto3.client('s3')

    try:
        # Retrieve the list of S3 buckets
        response = s3_client.list_buckets()
        buckets = response['Buckets']

        # Print the total number of buckets
        total_buckets = len(buckets)
        print(f"Total Buckets: {total_buckets}")

        # Counter for tracking the progress
        progress_counter = 1

        # Flag to track if any bucket with public access is found
        public_access_found = False

        # List to store bucket names without public access
        buckets_without_public_access = []

        # Iterate through each bucket and check for public access
        for bucket in buckets:
            bucket_name = bucket['Name']

            try:
                # Check public access through bucket policy
                bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                public_policy_access = 'Effect" : "Allow"' in str(bucket_policy)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    public_policy_access = False
                elif e.response['Error']['Code'] == 'IllegalLocationConstraintException':
                    print(f"Error: The location constraint for bucket {bucket_name} is incompatible.")
                    continue
                elif e.response['Error']['Code'] == 'AccessDenied':
                    print(f"Error: Access denied for bucket {bucket_name}. Skipping...")
                    continue
                else:
                    raise

            # Check public access through ACLs
            bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            acl_grants = bucket_acl.get('Grants', [])
            public_acl_access = any('AllUsers' in grant.get('Grantee', {}).get('URI', '') for grant in acl_grants)

            # Check Public Access Block Configuration
            try:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                public_access_block = response['PublicAccessBlockConfiguration']
                block_public_acls = public_access_block['BlockPublicAcls']
                ignore_public_acls = public_access_block['IgnorePublicAcls']
                block_public_policy = public_access_block['BlockPublicPolicy']
                restrict_public_buckets = public_access_block['RestrictPublicBuckets']
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    block_public_acls = ignore_public_acls = block_public_policy = restrict_public_buckets = False
                else:
                    raise

            # If public access is not detected, add the bucket name to the list
            if not any([public_policy_access, public_acl_access, block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                buckets_without_public_access.append(bucket_name)

            # Print progress in the console
            print(f"Progress: {progress_counter}/{total_buckets}", end='\r')
            progress_counter += 1

        # If no public access is detected in any bucket
        if not buckets_without_public_access:
            print("\nNo buckets without public access found.")
        else:
            print("\nBuckets without public access:")
            for bucket_name in buckets_without_public_access:
                print(f" - {bucket_name}")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    check_public_access()
