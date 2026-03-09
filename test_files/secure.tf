# Secure Terraform configuration for testing
# This file follows security best practices

resource "aws_security_group" "web_sg" {
  name        = "web-security-group"
  description = "Web server security group"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restricted to private network
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]  # SSH restricted to specific subnet
  }
}

resource "aws_db_instance" "main_db" {
  allocated_storage       = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  db_name                = "mydb"
  username               = "admin"
  password               = var.db_password  # Using variable instead of hardcoded
  storage_encrypted      = true             # Encryption enabled
  backup_retention_period = 7
  skip_final_snapshot    = false
  
  tags = {
    Environment = "production"
    Encrypted   = "true"
  }
}

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = true  # Encryption enabled
  
  tags = {
    Name      = "SecureDataVolume"
    Encrypted = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.main_bucket.id

  block_public_acls       = true  # Block public ACLs
  block_public_policy     = true  # Block public policies
  ignore_public_acls      = true  # Ignore public ACLs
  restrict_public_buckets = true  # Restrict public buckets
}

resource "aws_s3_bucket" "main_bucket" {
  bucket = "my-secure-bucket"
  
  tags = {
    Environment = "production"
    Security    = "enhanced"
  }
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "secure-vpc"
  }
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = var.flow_log_role_arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 90
}

resource "aws_cloudtrail" "main" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.main_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

variable "flow_log_role_arn" {
  description = "IAM role ARN for VPC flow logs"
  type        = string
}