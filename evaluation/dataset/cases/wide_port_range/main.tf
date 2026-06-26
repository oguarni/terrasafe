resource "aws_security_group" "all_ports" {
  name        = "all-ports-open"
  description = "Every port open to the world"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
