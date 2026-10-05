package terraform.security

# 1. Bloqueo de ACLs públicas
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_acls == false

    msg := sprintf(
        "CRITICAL: %q permite ACLs públicas",
        [resource.address],
    )
}

# 2. Bloqueo de políticas públicas
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_policy == false

    msg := sprintf(
        "CRITICAL: %q permite políticas públicas",
        [resource.address],
    )
}

# 3. Restricción de acceso público
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.ignore_public_acls == false

    msg := sprintf(
        "CRITICAL: %q no ignora ACLs públicas",
        [resource.address],
    )
}

# 4. Restricción de acceso entre cuentas
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.restrict_public_buckets == false

    msg := sprintf(
        "CRITICAL: %q permite acceso público entre cuentas",
        [resource.address],
    )
}

# Versionado obligatorio
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    resource.change.after.versioning_configuration.status != "Enabled"

    msg := sprintf(
        "HIGH: %q no tiene el versionado habilitado",
        [resource.address],
    )
}