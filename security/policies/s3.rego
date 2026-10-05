package terraform.security

deny contains msg if {
    resource := input.resource_changes[_]

    resource.type == "aws_s3_bucket_public_access_block"

    resource.change.after.block_public_acls == false

    msg := sprintf(
        "CRITICAL: S3 bucket %q allows public ACLs",
        [resource.address],
    )
}