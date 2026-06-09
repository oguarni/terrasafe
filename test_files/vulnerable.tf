# Vulnerable Terraform configuration for testing
# This file contains multiple security issues

resource "aws_security_group" "web_sg" {
  name        = "web-security-group"
  description = "Web server security group"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: Open SSH access from internet
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: Open HTTP access from internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # LOW: Unrestricted egress to the internet
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
  password               = "hardcoded123"  # CRITICAL: Hardcoded password
  storage_encrypted      = false           # HIGH: Unencrypted RDS instance
  publicly_accessible    = true            # CRITICAL: Database reachable from the internet
  backup_retention_period = 0
  skip_final_snapshot    = true
}

resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  associate_public_ip_address = true  # LOW: Auto-assigns a public IP

  # NOTE: no metadata_options block → IMDSv1 allowed (HIGH: SSRF → credential theft)
}

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false  # HIGH: Unencrypted EBS volume
  
  tags = {
    Name = "DataVolume"
  }
}

resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.main_bucket.id

  block_public_acls       = false  # HIGH: Public access enabled
  block_public_policy     = false  # HIGH: Public policy allowed
  ignore_public_acls      = false  # HIGH: Public ACLs not ignored
  restrict_public_buckets = false  # HIGH: Public buckets not restricted
}

resource "aws_s3_bucket" "main_bucket" {
  bucket = "my-vulnerable-bucket"
  
  tags = {
    Environment = "test"
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"  # HIGH: No aws_flow_log present — VPC traffic is unmonitored
  tags = {
    Name = "vulnerable-vpc"
  }
}
# NOTE: no aws_cloudtrail, no aws_cloudwatch_log_group → triggers missing_logging rule
# NOTE: no aws_flow_log → triggers missing_vpc_flow_logs rule