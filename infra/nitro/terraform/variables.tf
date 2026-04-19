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
  default     = "c6a.xlarge"
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

variable "existing_runtime_kms_key_arn" {
  type        = string
  description = "Existing customer-managed KMS key ARN to reuse for Nitro runtime secrets. When set, Terraform will not create a new runtime key."
  default     = null
}

variable "kms_attestation_pcrs" {
  type        = map(string)
  description = "Nitro enclave PCR values keyed by PCR index string (for example 0,1,2,3,8)."
  default     = {}
}

variable "kms_attestation_image_sha384" {
  type        = string
  description = "Optional Nitro ImageSha384 value. Defaults to PCR0 when omitted."
  default     = null
}

variable "kms_eif_signing_cert_sha256" {
  type        = string
  description = "SHA256 of the EIF signing certificate. Used for deployment metadata and tooling parity."
  default     = null
}

variable "kms_provisioner_principal_arns" {
  type        = list(string)
  description = "IAM principal ARNs that may pre-encrypt runtime secrets before the enclave starts."
  default     = []
}
