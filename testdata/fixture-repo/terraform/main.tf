resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"        # checkov: public access
}
