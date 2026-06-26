resource "aws_security_group" "ssh" {
  name        = "ssh-open"
  description = "SSH open to the world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
