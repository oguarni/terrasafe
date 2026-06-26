resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
}

resource "aws_iam_role_policy" "app_admin" {
  name = "app-admin-policy"
  role = aws_iam_role.app.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
