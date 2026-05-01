terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  cloud {
    # 1. Sign up free at https://app.terraform.io
    # 2. Create an organization and replace the value below
    # 3. Set TF_API_TOKEN in GitHub Actions secrets
    organization = "YOUR_TF_ORG_HERE"

    workspaces {
      name = "ai-security-monitoring"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
