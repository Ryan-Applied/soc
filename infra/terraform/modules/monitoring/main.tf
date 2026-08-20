# CloudWatch monitoring, dashboards, and alarms

variable "name_prefix" { type = string }
variable "ecs_cluster" { type = string }
variable "services" { type = map(any) }
variable "alarm_email" { type = string }
variable "rds_identifier" { type = string }

# --- SNS topic for alarms ---
resource "aws_sns_topic" "alarms" {
  name = "${var.name_prefix}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# --- ECS Service CPU alarms ---
resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  for_each = var.services

  alarm_name          = "${var.name_prefix}-${each.key}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "ECS ${each.key} CPU > 80% for 3 minutes"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    ClusterName = var.ecs_cluster
    ServiceName = each.key
  }
}

# --- ECS Service Memory alarms ---
resource "aws_cloudwatch_metric_alarm" "ecs_memory" {
  for_each = var.services

  alarm_name          = "${var.name_prefix}-${each.key}-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "ECS ${each.key} memory > 85% for 3 minutes"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  dimensions = {
    ClusterName = var.ecs_cluster
    ServiceName = each.key
  }
}

# --- RDS alarms ---
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.name_prefix}-rds-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU > 80% for 3 minutes"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions          = { DBInstanceIdentifier = var.rds_identifier }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.name_prefix}-rds-storage-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5000000000 # 5 GB
  alarm_description   = "RDS free storage < 5 GB"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions          = { DBInstanceIdentifier = var.rds_identifier }
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${var.name_prefix}-rds-connections-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS connections > 80"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  dimensions          = { DBInstanceIdentifier = var.rds_identifier }
}

# --- CloudWatch Dashboard ---
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-overview"
  dashboard_body = jsonencode({
    widgets = concat(
      # ECS CPU row
      [for i, svc in keys(var.services) : {
        type   = "metric"
        x      = (i % 3) * 8
        y      = floor(i / 3) * 6
        width  = 8
        height = 6
        properties = {
          title  = "${svc} CPU & Memory"
          region = "us-east-1"
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.ecs_cluster, "ServiceName", svc, { stat = "Average", label = "CPU %" }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", var.ecs_cluster, "ServiceName", svc, { stat = "Average", label = "Memory %" }],
          ]
          period = 300
          view   = "timeSeries"
          yAxis  = { left = { min = 0, max = 100 } }
        }
      }],
      # RDS widget
      [{
        type   = "metric"
        x      = 0
        y      = 18
        width  = 12
        height = 6
        properties = {
          title  = "RDS PostgreSQL"
          region = "us-east-1"
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.rds_identifier, { stat = "Average" }],
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", var.rds_identifier, { stat = "Average", yAxis = "right" }],
          ]
          period = 300
          view   = "timeSeries"
        }
      }],
    )
  })
}
