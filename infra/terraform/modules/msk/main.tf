# Amazon MSK (Managed Kafka) — event streaming

variable "name_prefix" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "instance_type" { type = string }
variable "ecs_security_group" { type = string }

resource "aws_security_group" "msk" {
  name_prefix = "${var.name_prefix}-msk-"
  vpc_id      = var.vpc_id
  description = "MSK Kafka access from ECS"

  ingress {
    from_port       = 9092
    to_port         = 9098
    protocol        = "tcp"
    security_groups = [var.ecs_security_group]
    description     = "Kafka from ECS tasks"
  }

  ingress {
    from_port       = 2181
    to_port         = 2181
    protocol        = "tcp"
    security_groups = [var.ecs_security_group]
    description     = "ZooKeeper from ECS tasks"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-msk-sg" }

  lifecycle { create_before_destroy = true }
}

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/msk/${var.name_prefix}"
  retention_in_days = 14
}

resource "aws_msk_cluster" "main" {
  cluster_name           = "${var.name_prefix}-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = length(var.private_subnet_ids)

  broker_node_group_info {
    instance_type   = var.instance_type
    client_subnets  = var.private_subnet_ids
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
      in_cluster    = true
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.main.arn
    revision = aws_msk_configuration.main.latest_revision
  }

  tags = { Name = "${var.name_prefix}-kafka" }
}

resource "aws_msk_configuration" "main" {
  name              = "${var.name_prefix}-kafka-config"
  kafka_versions    = ["3.6.0"]
  server_properties = <<-EOT
    auto.create.topics.enable=true
    default.replication.factor=2
    min.insync.replicas=1
    num.partitions=6
    log.retention.hours=168
  EOT
}

output "bootstrap_brokers" {
  value = aws_msk_cluster.main.bootstrap_brokers
}

output "zookeeper_connect" {
  value = aws_msk_cluster.main.zookeeper_connect_string
}
