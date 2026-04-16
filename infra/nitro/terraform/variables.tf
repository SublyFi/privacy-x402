variable "aws_region" {
  type        = string
  description = "AWS region for the Nitro deployment."
}

variable "project_name" {
  type        = string
  description = "Resource name prefix."
  default     = "a402-devnet"
}

variable "vpc_id" {
  type        = string
  description = "VPC id for the public NLB and parent EC2."
}

variable "nlb_subnet_ids" {
  type        = list(string)
  description = "At least two public subnet ids for the NLB."
}

variable "instance_subnet_id" {
  type        = string
  description = "Subnet id where the Nitro-capable parent EC2 instance will run."
}

variable "ami_id" {
  type        = string
  description = "AMI id for the parent EC2 host."
}

variable "instance_type" {
  type        = string
  description = "Nitro Enclave capable EC2 instance type."
  default     = "m7i.xlarge"
}

variable "key_name" {
  type        = string
  description = "Optional EC2 key pair name."
  default     = null
}

variable "ssh_ingress_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to SSH to the parent instance."
  default     = []
}

variable "snapshot_bucket_name" {
  type        = string
  description = "S3 bucket name for encrypted snapshots and WAL blobs."
}
