# AWS Secrets Manager for sensitive configuration

variable "name_prefix" { type = string }
variable "anthropic_api_key" {
  type      = string
  sensitive = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_secretsmanager_secret" "app" {
  name                    = "${var.name_prefix}/app-secrets"
  description             = "ALUSKORT SOC platform secrets"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    ANTHROPIC_API_KEY = var.anthropic_api_key
    DB_PASSWORD       = var.db_password
  })
}

output "secrets_arn" { value = aws_secretsmanager_secret.app.arn }
