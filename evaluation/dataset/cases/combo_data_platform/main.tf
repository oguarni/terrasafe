resource "aws_db_instance" "warehouse" {
  allocated_storage   = 100
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_instance" "ingest" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.large"
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_security_group" "ingest" {
  name        = "ingest"
  description = "Ingest tier"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_password" {
  type      = string
  sensitive = true
}
