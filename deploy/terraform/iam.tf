# ── EC2 Instance Role (allows ECS agent to call AWS APIs) ────────────────────

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_instance_role" {
  name               = "ecsInstanceRole"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_instance_core" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_role_policy_attachment" "ecs_instance_cloudwatch" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

resource "aws_iam_instance_profile" "ecs_node" {
  name = "ecsInstanceProfile"
  role = aws_iam_role.ecs_instance_role.name
}

# ── GitHub Actions Deployer User ──────────────────────────────────────────────

resource "aws_iam_user" "github_deployer" {
  name = "github-deployer"
}

resource "aws_iam_access_key" "github_deployer" {
  user = aws_iam_user.github_deployer.name
}

resource "aws_iam_user_policy_attachment" "deployer_ecr" {
  user       = aws_iam_user.github_deployer.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}

data "aws_iam_policy_document" "ecs_deploy" {
  statement {
    actions = [
      "ecs:RegisterTaskDefinition",
      "ecs:UpdateService",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ec2:DescribeInstances",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "deployer_ecs" {
  name   = "ecs-deploy"
  user   = aws_iam_user.github_deployer.name
  policy = data.aws_iam_policy_document.ecs_deploy.json
}
