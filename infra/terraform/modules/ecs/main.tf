# ECS Fargate cluster and service definitions

variable "name_prefix" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "aws_region" { type = string }
variable "account_id" { type = string }
variable "services" { type = map(any) }
variable "ecr_urls" { type = map(string) }
variable "alb_target_group_arn" { type = string }
variable "secrets_arn" { type = string }
variable "postgres_dsn" {
  type      = string
  sensitive = true
}
variable "redis_host" { type = string }
variable "kafka_brokers" { type = string }

# --- ECS Cluster ---
resource "aws_ecs_cluster" "main" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }

  tags = { Name = "${var.name_prefix}-cluster" }
}

resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/ecs/${var.name_prefix}/exec"
  retention_in_days = 14
}

# --- Security Group for ECS tasks ---
resource "aws_security_group" "ecs" {
  name_prefix = "${var.name_prefix}-ecs-"
  vpc_id      = var.vpc_id
  description = "ECS Fargate tasks"

  # Allow inter-service communication
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
    description = "Inter-service traffic"
  }

  # Allow ALB to reach dashboard
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "ALB to dashboard"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-ecs-sg" }

  lifecycle { create_before_destroy = true }
}

# --- IAM: Task execution role ---
resource "aws_iam_role" "ecs_exec" {
  name = "${var.name_prefix}-ecs-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_exec" {
  role       = aws_iam_role.ecs_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_exec_secrets" {
  name = "secrets-access"
  role = aws_iam_role.ecs_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.secrets_arn]
    }]
  })
}

# --- IAM: Task role ---
resource "aws_iam_role" "ecs_task" {
  name = "${var.name_prefix}-ecs-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ecs_task" {
  name = "task-permissions"
  role = aws_iam_role.ecs_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream", "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.secrets_arn]
      }
    ]
  })
}

# --- Log groups per service ---
resource "aws_cloudwatch_log_group" "svc" {
  for_each          = var.services
  name              = "/ecs/${var.name_prefix}/${each.key}"
  retention_in_days = 30
}

# --- Task Definitions ---
resource "aws_ecs_task_definition" "svc" {
  for_each = var.services

  family                   = "${var.name_prefix}-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = each.key
    image     = "${var.ecr_urls[each.key]}:latest"
    essential = true
    command   = each.value.command

    portMappings = each.value.port > 0 ? [{
      containerPort = each.value.port
      protocol      = "tcp"
    }] : []

    environment = [
      { name = "POSTGRES_DSN", value = var.postgres_dsn },
      { name = "REDIS_HOST", value = var.redis_host },
      { name = "KAFKA_BOOTSTRAP_SERVERS", value = var.kafka_brokers },
      { name = "ENVIRONMENT", value = "production" },
    ]

    secrets = [
      {
        name      = "ANTHROPIC_API_KEY"
        valueFrom = "${var.secrets_arn}:ANTHROPIC_API_KEY::"
      },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/${var.name_prefix}/${each.key}"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = each.key
      }
    }

    healthCheck = each.value.port > 0 ? {
      command     = ["CMD-SHELL", "curl -f http://localhost:${each.value.port}/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    } : null
  }])

  tags = { Service = each.key }
}

# --- ECS Services ---
resource "aws_ecs_service" "svc" {
  for_each = var.services

  name            = each.key
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.svc[each.key].arn
  desired_count   = each.value.count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = each.value.public ? [1] : []
    content {
      target_group_arn = var.alb_target_group_arn
      container_name   = each.key
      container_port   = each.value.port
    }
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  enable_execute_command = true

  tags = { Service = each.key }

  lifecycle {
    ignore_changes = [desired_count] # Allow autoscaling
  }
}

# --- Auto Scaling for dashboard ---
resource "aws_appautoscaling_target" "dashboard" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.main.name}/dashboard"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.svc["dashboard"]]
}

resource "aws_appautoscaling_policy" "dashboard_cpu" {
  name               = "${var.name_prefix}-dashboard-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.dashboard.resource_id
  scalable_dimension = aws_appautoscaling_target.dashboard.scalable_dimension
  service_namespace  = aws_appautoscaling_target.dashboard.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

output "cluster_name" { value = aws_ecs_cluster.main.name }
output "ecs_security_group_id" { value = aws_security_group.ecs.id }
