output "parent_instance_id" {
  value = aws_instance.parent.id
}

output "parent_public_ip" {
  value = aws_instance.parent.public_ip
}

output "nlb_dns_name" {
  value = aws_lb.public.dns_name
}

output "runtime_kms_key_arn" {
  value = aws_kms_key.runtime.arn
}

output "snapshot_bucket_name" {
  value = aws_s3_bucket.snapshots.bucket
}
