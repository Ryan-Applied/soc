# RDS PostgreSQL 16 — primary data store

variable "name_prefix" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "db_instance_class" { type = string }
variable "db_name" { type = string }
variable "db_username" { type = string }
variable "db_password" {
  type      = string
  sensitive = true
}

variable "multi_az" {
  type    = bool
  default = true
}
variable "ecs_security_group" { type = string }

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db"
  subnet_ids = var.private_subnet_ids
  tags       = { Name = "${var.name_prefix}-db-subnet-group" }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.name_prefix}-rds-"
  vpc_id      = var.vpc_id
  description = "RDS PostgreSQL access from ECS"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.ecs_security_group]
    description     = "PostgreSQL from ECS tasks"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-rds-sg" }

  lifecycle { create_before_destroy = true }
}

resource "aws_db_parameter_group" "main" {
  name_prefix = "${var.name_prefix}-pg16-"
  family      = "postgres16"

  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries > 1s
  }
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_db_instance" "main" {
  identifier     = "${var.name_prefix}-postgres"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.main.name

  allocated_storage     = 50
  max_allocated_storage = 200
  storage_type          = "gp3"
  storage_encrypted     = true

  multi_az            = var.multi_az
  publicly_accessible = false

  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-final-snapshot"

  performance_insights_enabled = true

  tags = { Name = "${var.name_prefix}-postgres" }
}

output "endpoint" { value = aws_db_instance.main.endpoint }
output "db_identifier" { value = aws_db_instance.main.identifier }
