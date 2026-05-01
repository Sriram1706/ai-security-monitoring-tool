resource "aws_ecs_cluster" "main" {
  name = "ai-security-cluster"
}

resource "aws_ecs_task_definition" "app" {
  family                = "ai-security-monitoring"
  network_mode          = "host"
  requires_compatibilities = ["EC2"]

  container_definitions = jsonencode([
    {
      name      = "db"
      image     = "postgres:16"
      essential = true
      environment = [
        { name = "POSTGRES_DB",       value = "ai_sec" },
        { name = "POSTGRES_USER",     value = "postgres" },
        { name = "POSTGRES_PASSWORD", value = var.db_password },
      ]
      mountPoints = [{
        sourceVolume  = "pg-data"
        containerPath = "/var/lib/postgresql/data"
        readOnly      = false
      }]
      healthCheck = {
        command     = ["CMD-SHELL", "pg_isready -U postgres -d ai_sec || exit 1"]
        interval    = 10
        timeout     = 5
        retries     = 5
        startPeriod = 15
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "db"
        }
      }
    },
    {
      name      = "backend"
      image     = "${aws_ecr_repository.backend.repository_url}:latest"
      essential = true
      portMappings = [{ containerPort = 8000, protocol = "tcp" }]
      environment = [
        { name = "DATABASE_URL",             value = "postgresql+psycopg2://postgres:${var.db_password}@localhost:5432/ai_sec" },
        { name = "JWT_SECRET",               value = var.jwt_secret },
        { name = "ACCESS_TOKEN_MINUTES",     value = "120" },
        { name = "BOOTSTRAP_ADMIN_EMAIL",    value = "admin@ai-sec.local" },
        { name = "BOOTSTRAP_ADMIN_PASSWORD", value = var.db_password },
        { name = "SQLITE_DB_PATH",           value = "/tmp/security.db" },
        { name = "OPENAI_API_KEY",           value = var.openai_api_key },
        { name = "THREAT_INTEL_ENABLED",     value = "false" },
        { name = "SUPPLY_CHAIN_SCAN_ENABLED", value = "true" },
      ]
      dependsOn = [{ containerName = "db", condition = "HEALTHY" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "backend"
        }
      }
    },
    {
      name      = "frontend"
      image     = "${aws_ecr_repository.frontend.repository_url}:latest"
      essential = true
      portMappings = [{ containerPort = 80, protocol = "tcp" }]
      dependsOn = [{ containerName = "backend", condition = "START" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "frontend"
        }
      }
    }
  ])

  volume {
    name = "pg-data"
    host_path = "/data/pgdata"
  }
}

resource "aws_ecs_service" "app" {
  name            = "ai-security-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "EC2"

  # Allow 0 healthy tasks during deploy — needed because host port 80
  # can only be bound by one task at a time on a single EC2 instance
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  depends_on = [aws_ecs_cluster.main]
}
