# ECR repositories for each microservice

variable "name_prefix" { type = string }
variable "services" { type = map(any) }

resource "aws_ecr_repository" "svc" {
  for_each = var.services
  name     = "${var.name_prefix}/${each.key}"

  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }

  tags = { Service = each.key }
}

resource "aws_ecr_lifecycle_policy" "svc" {
  for_each   = aws_ecr_repository.svc
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 20 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}

output "repository_urls" {
  value = { for k, v in aws_ecr_repository.svc : k => v.repository_url }
}
