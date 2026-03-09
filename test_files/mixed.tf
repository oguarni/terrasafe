# Mixed configuration - Some issues but not critical
# This file contains MEDIUM severity issues for testing

resource "aws_security_group" "app_sg" {
  name_description = "Application security group"
  
  # HTTP open but not SSH - MEDIUM risk
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Public HTTP - acceptable for web servers
  }
  
  # SSH restricted - GOOD
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Internal only
  }
}

resource "aws_db_instance" "app_db" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "postgres"
  engine_version       = "13.7"
  instance_class       = "db.t3.small"
  name                 = "appdb"
  username             = "dbadmin"
  password             = var.db_password  # Good - using variable
  storage_encrypted    = true            # Good - encrypted
  backup_retention_period = 3            # OK - some backups
  
  tags = {
    Environment = "staging"
    Encrypted   = "true"
  }
}

# Mixed S3 configuration
resource "aws_s3_bucket_public_access_block" "app_bucket" {
  bucket = aws_s3_bucket.app_bucket.id

  block_public_acls       = true   # Good
  block_public_policy     = true   # Good
  ignore_public_acls      = false  # MEDIUM: Could be better
  restrict_public_buckets = false  # MEDIUM: Could be better
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "my-app-staging-bucket"
  
  tags = {
    Environment = "staging"
    Security = "medium"
  }
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.0.0/16"  # MEDIUM: No aws_flow_log present
  tags = {
    Name = "mixed-vpc"
  }
}

resource "aws_cloudtrail" "app_trail" {
  name           = "app-trail"
  s3_bucket_name = aws_s3_bucket.app_bucket.bucket
  # CloudTrail present — satisfies missing_logging rule
}
# NOTE: aws_cloudtrail present → no missing_logging vuln
# NOTE: no aws_flow_log → triggers missing_vpc_flow_logs rule only
