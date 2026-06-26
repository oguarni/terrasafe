resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false

  tags = {
    Name = "data-volume"
  }
}
