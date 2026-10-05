terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region     = "eu-west-1"
  access_key = "test"
  secret_key = "test"

  endpoints {
    s3 = "http://localhost:4566"
  }

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_bucket" "test" {
  bucket = "gcsa-security-lab-test"
}

resource "aws_s3_bucket_public_access_block" "test" {
  bucket = aws_s3_bucket.test.id

  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

// resource "aws_s3_bucket_server_side_encryption_configuration" "test" {
//   bucket = aws_s3_bucket.test.id

//   rule {
//     apply_server_side_encryption_by_default {
//       sse_algorithm = "AES256"
//     }
//   }
// }

// resource "aws_kms_key" "test" {
//   description = "KMS key for GCSA security lab S3 bucket"
// }

resource "aws_s3_bucket_versioning" "test" {
  bucket = aws_s3_bucket.test.id

  versioning_configuration {
    status = "Enabled"
  }
}