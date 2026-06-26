resource "aws_db_instance" "public" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = true
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}
