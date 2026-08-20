# =============================================================================
# Input Variables — prompted by deploy.sh wizard
# =============================================================================

# ---------- AWS ----------
variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (prod, staging, dev)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be prod, staging, or dev."
  }
}

# ---------- Networking ----------
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "domain_name" {
  description = "Domain name for the dashboard (e.g. soc.example.com)"
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS (leave empty for HTTP-only)"
  type        = string
  default     = ""
}

# ---------- Database ----------
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_password" {
  description = "PostgreSQL master password"
  type        = string
  sensitive   = true
}

# ---------- Cache ----------
variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t4g.small"
}

# ---------- Kafka ----------
variable "kafka_instance_type" {
  description = "MSK broker instance type"
  type        = string
  default     = "kafka.t3.small"
}

# ---------- ECS Services ----------
variable "ecs_services" {
  description = "Map of ECS service definitions"
  type = map(object({
    cpu     = number
    memory  = number
    port    = number
    count   = number
    command = list(string)
    public  = bool
  }))
  default = {
    dashboard = {
      cpu     = 512
      memory  = 1024
      port    = 8080
      count   = 2
      command = ["uvicorn", "services.dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
      public  = true
    }
    context-gateway = {
      cpu     = 1024
      memory  = 2048
      port    = 8030
      count   = 2
      command = ["uvicorn", "context_gateway.api:app", "--host", "0.0.0.0", "--port", "8030"]
      public  = false
    }
    llm-router = {
      cpu     = 512
      memory  = 1024
      port    = 8031
      count   = 2
      command = ["uvicorn", "llm_router.api:app", "--host", "0.0.0.0", "--port", "8031"]
      public  = false
    }
    orchestrator = {
      cpu     = 1024
      memory  = 2048
      port    = 0
      count   = 2
      command = ["python", "-m", "orchestrator.service"]
      public  = false
    }
    entity-parser = {
      cpu     = 512
      memory  = 1024
      port    = 0
      count   = 1
      command = ["python", "-m", "entity_parser.service"]
      public  = false
    }
    ctem-normaliser = {
      cpu     = 512
      memory  = 1024
      port    = 0
      count   = 1
      command = ["python", "-m", "ctem_normaliser.service"]
      public  = false
    }
  }
}

# ---------- Secrets ----------
variable "anthropic_api_key" {
  description = "Anthropic API key for LLM calls"
  type        = string
  sensitive   = true
}

# ---------- Monitoring ----------
variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""
}
