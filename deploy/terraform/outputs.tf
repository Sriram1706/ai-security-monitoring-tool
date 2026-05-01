output "ec2_public_ip" {
  description = "Public IP of the ECS EC2 instance — your app URL is http://<this IP>"
  value       = aws_instance.ecs_node.public_ip
}

output "ecr_registry" {
  description = "ECR registry URL — use this as AWS_ECR_REGISTRY in GitHub Actions"
  value       = split("/", aws_ecr_repository.backend.repository_url)[0]
}

output "ecr_backend_url" {
  description = "Full ECR URL for the backend repository"
  value       = aws_ecr_repository.backend.repository_url
}

output "ecr_frontend_url" {
  description = "Full ECR URL for the frontend repository"
  value       = aws_ecr_repository.frontend.repository_url
}

output "github_deployer_access_key_id" {
  description = "AWS_ACCESS_KEY_ID to add as GitHub Actions secret for deployments"
  value       = aws_iam_access_key.github_deployer.id
}

output "github_deployer_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY to add as GitHub Actions secret for deployments"
  value       = aws_iam_access_key.github_deployer.secret
  sensitive   = true
}
