resource "aws_instance" "public" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required"
  }
}
