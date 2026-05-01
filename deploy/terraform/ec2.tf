# Latest ECS-optimized Amazon Linux 2 AMI (auto-updates via SSM)
data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
}

resource "aws_security_group" "ecs_node" {
  name        = "ecs-ai-security-sg"
  description = "Allow HTTP inbound and all outbound"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ecs_node" {
  ami                    = data.aws_ssm_parameter.ecs_ami.value
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.ecs_node.name
  key_name               = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.ecs_node.id]

  # Register with ECS cluster and prepare postgres data directory
  user_data = <<-EOF
    #!/bin/bash
    echo ECS_CLUSTER=ai-security-cluster >> /etc/ecs/ecs.config
    mkdir -p /data/pgdata
    chown 999:999 /data/pgdata
  EOF

  tags = {
    Name = "ecs-ai-security"
  }
}
