resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "SuperSecretP@ssw0rd123"
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = true
}
