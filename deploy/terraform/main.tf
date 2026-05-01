terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # State stored locally in deploy/terraform/terraform.tfstate (gitignored)
  # Run terraform commands from your terminal: cd deploy/terraform && terraform apply
  backend "local" {}
}

provider "aws" {
  region = var.aws_region
}
