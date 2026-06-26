resource "aws_security_group" "rdp" {
  name        = "rdp-open"
  description = "RDP open to the world"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
