resource "aws_s3_bucket" "screenshot_demo" {
  bucket = "muninn-screenshot-demo-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "screenshot_demo" {
  name        = "screenshot-demo-sg"
  description = "Intentionally insecure for Muninn screenshot"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
