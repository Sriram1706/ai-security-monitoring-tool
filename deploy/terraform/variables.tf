variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "db_password" {
  description = "PostgreSQL password used by all containers"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "Secret key for signing JWT tokens (run: openssl rand -hex 32)"
  type        = string
  sensitive   = true
}

variable "openai_api_key" {
  description = "OpenAI API key — leave empty to disable AI features"
  type        = string
  sensitive   = true
  default     = ""
}

variable "key_pair_name" {
  description = "EC2 key pair name for SSH access — leave null to skip (no SSH)"
  type        = string
  default     = null
  nullable    = true
}
