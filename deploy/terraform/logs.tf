resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/ai-security-monitoring"
  retention_in_days = 7
}
