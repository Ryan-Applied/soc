# =============================================================================
# ALUSKORT SOC Platform — AWS Production Deployment
# =============================================================================
# Architecture:
#   VPC (3 AZ) -> ALB -> ECS Fargate (services) + RDS Postgres + ElastiCache
#   + MSK (Kafka) + S3 (evidence/artifacts) + Secrets Manager + CloudWatch
#
# Run `bash deploy.sh` for guided setup, or:
#   terraform init && terraform plan -var-file=terraform.tfvars
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state (recommended for production)
  # backend "s3" {
  #   bucket         = "aluskort-terraform-state"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "aluskort-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aluskort-soc"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ---------- Data sources ----------
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "aluskort-${var.environment}"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)
  account_id  = data.aws_caller_identity.current.account_id

  common_tags = {
    Project     = "aluskort-soc"
    Environment = var.environment
  }
}

# =========================== MODULES ===========================

module "vpc" {
  source      = "./modules/vpc"
  name_prefix = local.name_prefix
  azs         = local.azs
  vpc_cidr    = var.vpc_cidr
}

module "ecr" {
  source      = "./modules/ecr"
  name_prefix = local.name_prefix
  services    = var.ecs_services
}

module "secrets" {
  source            = "./modules/secrets"
  name_prefix       = local.name_prefix
  anthropic_api_key = var.anthropic_api_key
  db_password       = var.db_password
}

module "rds" {
  source             = "./modules/rds"
  name_prefix        = local.name_prefix
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  db_instance_class  = var.db_instance_class
  db_name            = "aluskort"
  db_username        = "aluskort"
  db_password        = var.db_password
  multi_az           = var.environment == "prod"
  ecs_security_group = module.ecs.ecs_security_group_id
}

module "elasticache" {
  source             = "./modules/elasticache"
  name_prefix        = local.name_prefix
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_type          = var.redis_node_type
  ecs_security_group = module.ecs.ecs_security_group_id
}

module "msk" {
  source             = "./modules/msk"
  name_prefix        = local.name_prefix
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  instance_type      = var.kafka_instance_type
  ecs_security_group = module.ecs.ecs_security_group_id
}

module "alb" {
  source            = "./modules/alb"
  name_prefix       = local.name_prefix
  vpc_id            = module.vpc.vpc_id
  public_subnet_ids = module.vpc.public_subnet_ids
  certificate_arn   = var.acm_certificate_arn
  domain_name       = var.domain_name
}

module "ecs" {
  source               = "./modules/ecs"
  name_prefix          = local.name_prefix
  vpc_id               = module.vpc.vpc_id
  private_subnet_ids   = module.vpc.private_subnet_ids
  aws_region           = var.aws_region
  account_id           = local.account_id
  services             = var.ecs_services
  ecr_urls             = module.ecr.repository_urls
  alb_target_group_arn = module.alb.dashboard_target_group_arn
  secrets_arn          = module.secrets.secrets_arn

  # Connection strings passed as env vars
  postgres_dsn  = "postgresql://aluskort:${var.db_password}@${module.rds.endpoint}/aluskort"
  redis_host    = module.elasticache.endpoint
  kafka_brokers = module.msk.bootstrap_brokers

  depends_on = [module.rds, module.elasticache, module.msk, module.alb]
}

module "monitoring" {
  source         = "./modules/monitoring"
  name_prefix    = local.name_prefix
  ecs_cluster    = module.ecs.cluster_name
  services       = var.ecs_services
  alarm_email    = var.alarm_email
  rds_identifier = module.rds.db_identifier
}
