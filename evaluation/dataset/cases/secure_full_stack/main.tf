resource "aws_security_group" "web" {
  name        = "web"
  description = "Web tier, private only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = false
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}

resource "aws_instance" "app" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "tv-eval-secure-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = var.flow_role_arn
  log_destination = aws_cloudwatch_log_group.flow.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/flow"
  retention_in_days = 90
}

resource "aws_cloudtrail" "main" {
  name                       = "trail"
  s3_bucket_name             = aws_s3_bucket.logs.bucket
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "flow_role_arn" {
  type = string
}
