resource "aws_security_group" "ssh_v6" {
  name        = "ssh-open-ipv6"
  description = "SSH open to the world over IPv6"

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
