resource "aws_security_group" "parent" {
  name        = "${var.project_name}-parent"
  description = "A402 parent ingress"
  vpc_id      = var.vpc_id

  ingress {
    description = "Public facilitator ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = length(var.ssh_ingress_cidrs) == 0 ? [] : [1]

    content {
      description = "SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.ssh_ingress_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "parent_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "parent" {
  name               = "${var.project_name}-parent"
  assume_role_policy = data.aws_iam_policy_document.parent_assume_role.json
}

data "aws_iam_policy_document" "parent_runtime" {
  statement {
    sid = "SnapshotStore"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.snapshots.arn,
      "${aws_s3_bucket.snapshots.arn}/*",
    ]
  }

  statement {
    sid = "KmsProxy"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GenerateRandom",
    ]

    resources = [aws_kms_key.runtime.arn]
  }

  statement {
    sid = "CloudWatchLogs"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }

  statement {
    sid = "SsmSession"

    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "parent_runtime" {
  name   = "${var.project_name}-parent-runtime"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.parent_runtime.json
}

resource "aws_iam_instance_profile" "parent" {
  name = "${var.project_name}-parent"
  role = aws_iam_role.parent.name
}

resource "aws_s3_bucket" "snapshots" {
  bucket = var.snapshot_bucket_name
}

resource "aws_s3_bucket_versioning" "snapshots" {
  bucket = aws_s3_bucket.snapshots.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "runtime" {
  description             = "A402 Nitro runtime key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "runtime" {
  name          = "alias/${var.project_name}-runtime"
  target_key_id = aws_kms_key.runtime.key_id
}

resource "aws_instance" "parent" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.instance_subnet_id
  vpc_security_group_ids = [aws_security_group.parent.id]
  iam_instance_profile   = aws_iam_instance_profile.parent.name
  key_name               = var.key_name

  enclave_options {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-parent"
  }
}

resource "aws_lb" "public" {
  name               = substr(replace("${var.project_name}-nlb", "_", "-"), 0, 32)
  internal           = false
  load_balancer_type = "network"
  subnets            = var.nlb_subnet_ids
}

resource "aws_lb_target_group" "parent_443" {
  name        = substr(replace("${var.project_name}-443", "_", "-"), 0, 32)
  port        = 443
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = var.vpc_id

  health_check {
    protocol = "TCP"
    port     = "443"
  }
}

resource "aws_lb_target_group_attachment" "parent_443" {
  target_group_arn = aws_lb_target_group.parent_443.arn
  target_id        = aws_instance.parent.id
  port             = 443
}

resource "aws_lb_listener" "public_443" {
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.parent_443.arn
  }
}
