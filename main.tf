# route53 zone for simtooreal
data "aws_route53_zone" "zone_simtooreal" {
  name    = "simtooreal.com"
  private_zone = false
}

# route53 record for database so that no long database endpoints need to be remembered
resource "aws_route53_record" "record_database_simtooreal" {
  name    = "database.simtooreal.com"
  zone_id = data.aws_route53_zone.zone_simtooreal.id
  type    = "CNAME"
  ttl     = 30

  records = [aws_rds_cluster.simtooreal.endpoint]
}

# route53 record for private EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_private_simtooreal" {
  name    = "private.simtooreal.com"
  zone_id = data.aws_route53_zone.zone_simtooreal.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.simtooreal_private.private_ip]
}

# route53 record for public EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_public_simtooreal" {
  name    = "public.simtooreal.com"
  zone_id = data.aws_route53_zone.zone_simtooreal.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.simtooreal_public.public_ip]
}

# route53 record for short url
resource "aws_route53_record" "short_simtooreal" {
  name    = "simtooreal.com"
  zone_id = data.aws_route53_zone.zone_simtooreal.id
  type    = "A"

  alias {
    name                   = aws_lb.simtooreal.dns_name
    zone_id                = aws_lb.simtooreal.zone_id
    evaluate_target_health = true
  }
}

# route53 record for full url
resource "aws_route53_record" "simtooreal" {
  name    = "www.simtooreal.com"
  zone_id = data.aws_route53_zone.zone_simtooreal.id
  type    = "A"

  alias {
    name                   = aws_lb.simtooreal.dns_name
    zone_id                = aws_lb.simtooreal.zone_id
    evaluate_target_health = true
  }
}

# simtooreal certificate managed by Terraform
resource "aws_acm_certificate" "simtooreal" {
  domain_name       = "*.simtooreal.com"
  validation_method = "DNS"
  subject_alternative_names = ["simtooreal.com"]

  tags = {
    Description = "simtooreal certificate managed by Terraform"
    Name        = "simtooreal"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# the listener needs a cert as well
resource "aws_lb_listener_certificate" "simtooreal" {
  listener_arn    = aws_lb_listener.simtooreal.arn
  certificate_arn = aws_acm_certificate.simtooreal.arn
}

# validation record for simtooreal cert
resource "aws_route53_record" "simtooreal_validation" {
  name    = sort(aws_acm_certificate.simtooreal.domain_validation_options[*].resource_record_name)[0]
  type    = sort(aws_acm_certificate.simtooreal.domain_validation_options[*].resource_record_type)[0]
  records = [sort(aws_acm_certificate.simtooreal.domain_validation_options[*].resource_record_value)[0]]
  zone_id = data.aws_route53_zone.zone_simtooreal.id
  ttl     = "300"
}

# cert for simtooreal
resource "aws_acm_certificate_validation" "simtooreal" {
  certificate_arn         = aws_acm_certificate.simtooreal.arn
  validation_record_fqdns = [aws_route53_record.simtooreal_validation.fqdn]
}

### IAM/ECR

# ecr for holding all images
resource "aws_ecr_repository" "simtooreal" {
  name                 = "simtooreal"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ecr admin role for simtooreal
resource "aws_iam_user" "simtooreal_ecr_admin" {
  name = "simtooreal_ecr_admin"

  tags = {
    tag-key = "simtooreal"
  }
}

# ecr admin policy for simtooreal
resource "aws_iam_user_policy" "simtooreal_ecr_admin" {
  name = "simtooreal_ecr_admin"
  user = aws_iam_user.simtooreal_ecr_admin.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ecr:*",
            "Resource": "*"
        }
    ]
}
EOF
}

# instance profile for reading s3 from an EC2 instance
# which could be useful for a bastion or prepoluating instances with files
resource "aws_iam_instance_profile" "simtooreal_s3_public_read" {
  name     = "simtooreal_s3_public_read"
}

resource "aws_iam_instance_profile" "simtooreal_s3_private_read" {
  name     = "simtooreal_s3_private_read"
}

# instance profile for ecs
resource "aws_iam_instance_profile" "simtooreal_ecs" {
  name     = "simtooreal_ecs"
}

# task execution ecs role for simtooreal
resource "aws_iam_role" "simtooreal_ecs_task_execution" {
  name = "simtooreal_ecs_task_execution"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF

# this is necessary for hosting database passwords and hosts in AWS Systems Manager
# for convenience and so passwords are less likely to be stored on local machines
inline_policy {
  name = "my_inline_policy"

  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameters"
      ],
      "Resource": [
        "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/POSTGRESQL_HOST",
        "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/POSTGRESQL_PASSWORD",
        "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/OPENAI_API_KEY"
      ]
    }
  ]
})
}
}

# s3 reading role for ECS tasks
resource "aws_iam_role" "simtooreal_s3_read" {
  name = "simtooreal_s3_read"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# ECS task role
resource "aws_iam_role" "simtooreal_ecs" {
  name = "simtooreal_ecs"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# ECS task execution role policy attachment
resource "aws_iam_role_policy_attachment" "simtooreal_ecs_task_execution" {
  role       = aws_iam_role.simtooreal_ecs_task_execution.name
  policy_arn = aws_iam_policy.simtooreal_ecs_task_execution.arn
}

# ECS task  role policy attachment
resource "aws_iam_role_policy_attachment" "simtooreal_ecs" {
  role       = aws_iam_role.simtooreal_ecs.name
  policy_arn = aws_iam_policy.simtooreal_ecs.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "simtooreal_s3_public_read" {
  role       = aws_iam_role.simtooreal_s3_read.name
  policy_arn = aws_iam_policy.simtooreal_s3_public_read.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "simtooreal_s3_private_read" {
  role       = aws_iam_role.simtooreal_s3_read.name
  policy_arn = aws_iam_policy.simtooreal_s3_private_read.arn
}

# IAM policy for task execution
resource "aws_iam_policy" "simtooreal_ecs_task_execution" {
  name               = "simtooreal_ecs_task_execution"
  description        = "Policy to allow ECS to execute tasks"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

# IAM policy for reading s3 in simtooreal
resource "aws_iam_policy" "simtooreal_s3_public_read" {
  name               = "simtooreal_s3_public_read"
  description        = "Policy to allow S3 reading of bucket simtooreal-public"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:s3:::simtooreal-public/*",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_ACCESS_KEY_ID",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_SECRET_ACCESS_KEY",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/OPENAI_API_KEY"
            ]
        }
    ]
}
EOF
}

# IAM policy for reading s3 in simtooreal
resource "aws_iam_policy" "simtooreal_s3_private_read" {
  name               = "simtooreal_s3_private_read"
  description        = "Policy to allow S3 reading of bucket simtooreal-private and ssm"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:s3:::simtooreal-private/*",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_ACCESS_KEY_ID",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_SECRET_ACCESS_KEY",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/OPENAI_API_KEY"
            ]
        }
    ]
}
EOF
}

# IAM policy for ECS
resource "aws_iam_policy" "simtooreal_ecs" {
  name               = "simtooreal_ecs"
  description        = "Policy to allow ECS access"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeTags",
                "ecs:CreateCluster",
                "ecs:DeregisterContainerInstance",
                "ecs:DiscoverPollEndpoint",
                "ecs:Poll",
                "ecs:RegisterContainerInstance",
                "ecs:StartTelemetrySession",
                "ecs:UpdateContainerInstancesState",
                "ecs:Submit*",
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

### Networking and subnets

# AWS VPC for simtooreal
resource "aws_vpc" "simtooreal" {
  cidr_block = "172.17.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
    Name        = "simtooreal"
  }
}

# Fetch Availability Zones in the current region
data "aws_availability_zones" "simtooreal" {
}

# Create var.az_count private subnets, each in a different AZ
resource "aws_subnet" "simtooreal_private" {
  count             = var.az_count
  cidr_block        = cidrsubnet(aws_vpc.simtooreal.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.simtooreal.names[count.index]
  vpc_id            = aws_vpc.simtooreal.id

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
  }
}

# Create var.az_count public subnets, each in a different AZ
resource "aws_subnet" "simtooreal_public" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.simtooreal.cidr_block,
    8,
    var.az_count + count.index,
  )
  availability_zone       = data.aws_availability_zones.simtooreal.names[count.index]
  vpc_id                  = aws_vpc.simtooreal.id
  map_public_ip_on_launch = true

  tags = {
    Description = "simtooreal public subnet managed by Terraform"
    Environment = "production"
  }
}

# Create var.az_count rds subnets, each in a different AZ
resource "aws_subnet" "simtooreal_rds" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.simtooreal.cidr_block,
    8,
    2 * var.az_count + 1 + count.index,
  )
  availability_zone = data.aws_availability_zones.simtooreal.names[count.index]
  vpc_id            = aws_vpc.simtooreal.id

  tags = {
    Description = "simtooreal RDS subnet managed by Terraform"
    Environment = "production"
  }
}

# IGW for the public subnet
resource "aws_internet_gateway" "simtooreal" {
  vpc_id = aws_vpc.simtooreal.id
}

# Route the public subnet traffic through the IGW
resource "aws_route" "simtooreal_internet_access" {
  route_table_id         = aws_vpc.simtooreal.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.simtooreal.id
}

# Create a NAT gateway with an EIP for each private subnet to get internet connectivity
resource "aws_eip" "simtooreal" {
  count      = var.az_count
  vpc        = true
  depends_on = [aws_internet_gateway.simtooreal]

  tags = {
    Description = "simtooreal gateway EIP managed by Terraform"
    Environment = "production"
  }
}

# NAT gateway for internet access
resource "aws_nat_gateway" "simtooreal" {
  count         = var.az_count
  subnet_id     = element(aws_subnet.simtooreal_public.*.id, count.index)
  allocation_id = element(aws_eip.simtooreal.*.id, count.index)

  tags = {
    Description = "simtooreal gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# Create a new route table for the private subnets
# And make it route non-local traffic through the NAT gateway to the internet
resource "aws_route_table" "simtooreal_private" {
  count  = var.az_count
  vpc_id = aws_vpc.simtooreal.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.simtooreal.*.id, count.index)
  }

  tags = {
    Description = "simtooreal gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# RDS route table for simtooreal
resource "aws_route_table" "simtooreal_rds" {
  count  = var.az_count
  vpc_id = aws_vpc.simtooreal.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.simtooreal.*.id, count.index)
  }

  tags = {
    Description = "simtooreal RDS route table managed by Terraform"
    Environment = "production"
  }
}

# Explicitely associate the newly created route tables to the private subnets (so they don't default to the main route table)
resource "aws_route_table_association" "simtooreal_private" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.simtooreal_private.*.id, count.index)
  route_table_id = element(aws_route_table.simtooreal_private.*.id, count.index)
}

resource "aws_route_table_association" "rsimtooreal_rds" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.simtooreal_rds.*.id, count.index)
  route_table_id = element(aws_route_table.simtooreal_rds.*.id, count.index)
}

### RDS

# subnet used by rds
resource "aws_db_subnet_group" "simtooreal" {
  name        = "simtooreal"
  description = "simtooreal RDS Subnet Group managed by Terraform"
  subnet_ids  = aws_subnet.simtooreal_rds.*.id
}

# Security Group for resources that want to access the database
resource "aws_security_group" "simtooreal_db_access" {
  vpc_id      = aws_vpc.simtooreal.id
  name        = "simtooreal_db_access"
  description = "simtooreal allow access to RDS, managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.simtooreal.cidr_block]
  }
}

# database security group
resource "aws_security_group" "simtooreal_rds" {
  name        = "simtooreal_rds"
  description = "simtooreal RDS security group, managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  //allow traffic for TCP 5432
  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.simtooreal_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# database cluster instances for simtooreal
resource "aws_rds_cluster_instance" "simtooreal" {
  # WARNING: Setting count to anything less than 2 reduces
  # the reliability of your system, many times an instance
  # failure has occured requiring a hot switch to a
  # secondary instance, if there is nothing to switch to
  # you may regret setting count to 1, consider reliability
  # and weigh it against infrastructure cost
  count                = 2
  cluster_identifier   = aws_rds_cluster.simtooreal.id
  instance_class       = "db.r4.large"
  db_subnet_group_name = aws_db_subnet_group.simtooreal.name
  engine               = "aurora-postgresql"
  engine_version       = "12.8"
}

# database cluster for simtooreal
resource "aws_rds_cluster" "simtooreal" {
  cluster_identifier        = "simtooreal"
  #availability_zones        = ["us-east-1a", "us-east-1b", "us-east-1c"]
  database_name             = "simtooreal"
  master_username           = "postgres"
  master_password           = var.db_password
  db_subnet_group_name      = aws_db_subnet_group.simtooreal.name
  engine                    = "aurora-postgresql"
  engine_version            = "12.8"
  vpc_security_group_ids    = [aws_security_group.simtooreal_rds.id]
  skip_final_snapshot       = "true"
  final_snapshot_identifier = "foo"
  storage_encrypted         = "true"
  #snapshot_identifier      = "simtooreal"
}

### Elasticache

# Security Group for resources that want to access redis
resource "aws_security_group" "simtooreal_redis_access" {
  vpc_id      = aws_vpc.simtooreal.id
  name        = "simtooreal_redis_access"
  description = "simtooreal redis access security group managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.simtooreal.cidr_block]
  }
}

resource "aws_security_group" "simtooreal_redis" {
  name        = "simtooreal_redis"
  vpc_id      = aws_vpc.simtooreal.id
  description = "simtooreal Redis Security Group managed by Terraform"

  //allow traffic for TCP 6379
  ingress {
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.simtooreal_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# public security group for load balancers and bastions
resource "aws_security_group" "simtooreal_public" {
  name        = "simtooreal_public"
  description = "simtooreal public security group managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  # allows ssh attempts from my IP address
  # you should change this to your IP address
  # or your corporate network
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["69.181.183.147/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### Elasticache

# # elasticache for simtooreal
# resource "aws_elasticache_subnet_group" "simtooreal" {
#   name       = "simtooreal"
#   subnet_ids = aws_subnet.simtooreal_private.*.id
# }

# # elasticache cluster for simtooreal
# resource "aws_elasticache_cluster" "simtooreal" {
#   cluster_id           = "simtooreal"
#   engine               = "redis"
#   node_type            = "cache.m5.large"
#   port                 = 6379
#   num_cache_nodes      = 1
#   security_group_ids   = [aws_security_group.simtooreal_redis.id]
#   subnet_group_name    = aws_elasticache_subnet_group.simtooreal.name
#   parameter_group_name = aws_elasticache_parameter_group.simtooreal.name
# }

# # elasticache parameter group for simtooreal
# resource "aws_elasticache_parameter_group" "simtooreal" {
#   name   = "redis-28-simtooreal"
#   family = "redis6.x"

#   parameter {
#     name  = "timeout"
#     value = "500"
#   }
# }

### AWS instances

resource "aws_key_pair" "simtooreal" {
  key_name   = "simtooreal"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC60teZFO7BuQVwHSUewqOFGo7Iko16pF/vpio8p0K4PR29KG4oaKd4lRHx0WwX5NlLTxEI5xXQWAN9sRQMz60UDnURKnGbjiy+QI/mL3Ivkt4YV6gEfGYdVChJE6bYpnmUbPn8e27JcIJkBcDEATTEZEvSWi8xNhXWOr3I4m/Jc7OOOZAk7R9roqFlsNQrOCizc543PxCLLKafwFcDNUg+h8EOO3+PVZJziAllRTx53WxYbOUZ1tSXwaiJkXSLhVmSZQU6gXuzjlUe2ZAYwW9XzQj8xvPjFJIgizJthnbFxiAn6BygM+/4YdT+SjdpG1Y3NamXgBPQPKWFX8vBkwxVIGywDqpMVlI8L1DgbU4ISVmkHj+kG8t7iX9NF73fG9M414SBpIZSO7lsXz5rHqoz7VZe5DDl5piVV/thXwaAMMm1kerF1GlWcvUxsABv4yD2DnuqMVPz77dP1abOVpRTr7NcSvQCFv4vcMO+0CAGO/RIn3vYawjLvBFEeICsd35mnWF+PDg4QiSycJpUX9wFnZKsbI+pOEfexHqseuiS+PTOgROVonC7PUzYjFbxT3SRKRsiJxNxmRtbaEjWXZpsEFjDb/ifs9K06mqTF6MqFYXVs4AhTxDuhqQ9EOBg/LG+JUIj76o4cl7VkUJxhYyP9MNO1Ze6AVl7/xmzigsEFQ== chase.brignac@example.com"
}

# public facing instance through which maintenance work is done
# t3a.micro has enough memory to run a Duo bastion but t3a.nano will save money
resource "aws_instance" "simtooreal_public" {
  ami                         = "ami-0fa37863afb290840"
  instance_type               = "t3a.micro"
  subnet_id                   = aws_subnet.simtooreal_public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.simtooreal_s3_public_read.name
  vpc_security_group_ids      = [aws_security_group.simtooreal_public.id]
  key_name                    = aws_key_pair.simtooreal.key_name
  depends_on                  = [aws_s3_bucket_object.simtooreal_public]
  user_data                   = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.simtooreal_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.simtooreal_secret_access_key.value}\necho $AWS_SECRET_ACCESS_KEY\necho $AWS_ACCESS_KEY_ID\nexport AWS_DEFAULT_REGION=us-east-1\nsudo apt-get update -y\nsudo apt-get install awscli -y\nsudo apt-get install awscli -y\naws s3 cp s3://simtooreal-public/bastion.tar.gz ./\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\ncurl -fsSL https://download.docker.com/linux/ubuntu/gpg  | apt-key add -\nadd-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable'\napt-get -y install docker-ce\nsystemctl start docker\napt-get install -y docker-compose\nsystemctl enable docker\ntar -zxvf bastion.tar.gz\ncd bastion/examples/compose\ndocker-compose up --build"
  # to troubleshoot your user_data logon to the instance and run this
  #cat /var/log/cloud-init-output.log

  root_block_device {
    volume_size = "20"
    volume_type = "standard"
  }

  # lifecycle {
  #   ignore_changes = [user_data]
  # }

  tags = {
    Name = "simtooreal_public"
  }
}

# private instance inside the private subnet
# reaching RDS is done through this instance
resource "aws_instance" "simtooreal_private" {
  # These can be ecs optimized AMI if Amazon Linux OS is your thing
  # or you can even add an ECS compatible AMI, update instance type to t2.2xlarge
  # add to the user_data "ECS_CLUSTER= simtooreal >> /etc/ecs/ecs.config"
  # and add the iam_instance_profile of aws_iam_instance_profile.simtooreal_ecs.name
  # and you would then be able to use this instance in ECS
  ami           = "ami-0fa37863afb290840"
  instance_type = "t2.nano"
  subnet_id     = aws_subnet.simtooreal_private[0].id

  vpc_security_group_ids      = [aws_security_group.simtooreal_ecs.id]
  key_name                    = aws_key_pair.simtooreal.key_name
  iam_instance_profile        = aws_iam_instance_profile.simtooreal_s3_private_read.name
  depends_on                  = [aws_s3_bucket_object.simtooreal_private]
  user_data                   = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nsudo apt-get update -y\nsudo apt-get install awscli -y\necho $USER\necho ECS_CLUSTER=simtooreal > /etc/ecs/ecs.config\napt-add-repository --yes --update ppa:ansible/ansible\napt -y install ansible\napt install postgresql-client-common\napt-get -y install postgresql\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.simtooreal_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.simtooreal_secret_access_key.value}\nexport AWS_DEFAULT_REGION=us-east-1\naws s3 cp s3://simtooreal-private/simtooreal.tar.gz ./\ntar -zxvf simtooreal.tar.gz\nmv simtooreal data\napt install python3-pip -y\napt-get install tmux"
  # to troubleshoot your user_data logon to the instance and run this
  #cat /var/log/cloud-init-output.log

  # lifecycle {
  #   ignore_changes = [user_data]
  # }
  
  root_block_device {
    volume_size = "100"
    volume_type = "standard"
  }

  tags = {
    Name = "simtooreal_private"
  }
}

### ECS

# ECS service for the backend
resource "aws_ecs_service" "simtooreal_backend" {
  name            = "simtooreal_backend"
  cluster         = aws_ecs_cluster.simtooreal.id
  task_definition = aws_ecs_task_definition.simtooreal_backend.family
  desired_count   = var.app_count
  launch_type     = "FARGATE"
  force_new_deployment = true

  network_configuration {
    security_groups = [aws_security_group.simtooreal_ecs.id]
    subnets         = aws_subnet.simtooreal_private.*.id
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.simtooreal_backend.id
    container_name   = "simtooreal-backend"
    container_port   = "8080"
  }

  depends_on = [aws_lb_listener.simtooreal]

  tags = {
    Description = "simtooreal Elastic Container Service managed by Terraform"
    Environment = "production"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# in case we ever want to start using reserved instances to try and save money
# resource "aws_ecs_service" "simtooreal_backend_reserved" {
#   name            = "simtooreal_backend_reserved"
#   cluster         = aws_ecs_cluster.simtooreal.id
#   task_definition = aws_ecs_task_definition.simtooreal_backend.arn
#   desired_count   = var.app_count
#   launch_type     = "EC2"
#
#   network_configuration {
#     security_groups = [aws_security_group.simtooreal_ecs.id]
#     subnets         = aws_subnet.simtooreal_private.*.id
#   }
#
#   load_balancer {
#     target_group_arn = aws_lb_target_group.simtooreal_backend.id
#     container_name   = "simtooreal_backend"
#     container_port   = "8080"
#   }
#
#   depends_on = [aws_lb_listener.simtooreal]
#
#   tags = {
#     Description = "simtooreal reserved Elastic Container Service managed by Terraform"
#     Environment = "production"
#   }
#
#   lifecycle {
#     ignore_changes = [desired_count]
#   }
# }

### Autoscaling

# autoscaling target for simtooreal
resource "aws_appautoscaling_target" "simtooreal_backend" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.simtooreal.name}/${aws_ecs_service.simtooreal_backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  max_capacity       = var.ecs_autoscale_max_instances
  min_capacity       = 1
}

resource "aws_cloudwatch_metric_alarm" "simtooreal_backend_memory_utilization_high" {
  alarm_name          = "simtooreal_backend_memory_utilization_high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 60

  dimensions = {
    ClusterName = aws_ecs_cluster.simtooreal.name
    ServiceName = aws_ecs_service.simtooreal_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.simtooreal_backend_memory_utilization_high.arn]
}

# memory metric alarm
resource "aws_cloudwatch_metric_alarm" "simtooreal_backend_memory_utilization_low" {
  alarm_name          = "simtooreal_backend_memory_utilization_high"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.simtooreal.name
    ServiceName = aws_ecs_service.simtooreal_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.simtooreal_backend_memory_utilization_low.arn]
}

# memory metric alarm
resource "aws_appautoscaling_policy" "simtooreal_backend_memory_utilization_high" {
  name               = "simtooreal_backend_memory_utilization_high"
  service_namespace  = aws_appautoscaling_target.simtooreal_backend.service_namespace
  resource_id        = aws_appautoscaling_target.simtooreal_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.simtooreal_backend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}

# memory metric alarm policy
resource "aws_appautoscaling_policy" "simtooreal_backend_memory_utilization_low" {
  name               = "simtooreal_backend_memory_utilization_low"
  service_namespace  = aws_appautoscaling_target.simtooreal_backend.service_namespace
  resource_id        = aws_appautoscaling_target.simtooreal_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.simtooreal_backend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 300
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

# backend task definition
resource "aws_ecs_task_definition" "simtooreal_backend" {
  depends_on = [
    aws_lb.simtooreal,
    #aws_elasticache_cluster.simtooreal,
    aws_rds_cluster.simtooreal,
  ]
  family                   = "simtooreal"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024
  memory                   = 4096
  execution_role_arn       = aws_iam_role.simtooreal_ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "simtooreal-backend"
      image     = "danriti/nginx-gunicorn-flask"
      cpu       = 256
      memory    = 512
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ],
      "mountPoints": [],
      "logConfiguration": {
          "logDriver": "awslogs",
          "options": {
              "awslogs-group": "/ecs/simtooreal",
              "awslogs-region": "us-east-1",
              "awslogs-stream-prefix": "simtooreal-backend"
          }
      },
      "volumesFrom": [],
      "environment": []
    }
  ])
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "simtooreal" {
  name              = "/ecs/simtooreal"
  retention_in_days = 30

  tags = {
    Environment = "production"
    Application = "simtooreal"
  }
}

# This needs to be integrated completely into our container_definitions of our aws_ecs_task_definition
resource "aws_cloudwatch_log_stream" "simtooreal" {
  name           = "simtooreal"
  log_group_name = aws_cloudwatch_log_group.simtooreal.name
}

# ECS cluster for simtooreal
resource "aws_ecs_cluster" "simtooreal" {
  name = "simtooreal"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Traffic to the ECS Cluster should only come from the ALB, DB, or elasticache
resource "aws_security_group" "simtooreal_ecs" {
  name        = "simtooreal_ecs"
  description = "simtooreal Elastic Container Service (ECS) security group managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  ingress {
    protocol  = "tcp"
    from_port = "80"
    to_port   = "80"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.simtooreal_lb.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.simtooreal_lb.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "5432"
    to_port         = "5432"
    security_groups = [aws_security_group.simtooreal_db_access.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "6379"
    to_port         = "6379"
    security_groups = [aws_security_group.simtooreal_redis_access.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.simtooreal.cidr_block]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### ALB

# load balancer for simtooreal
resource "aws_lb" "simtooreal" {
  name            = "simtooreal"
  subnets         = aws_subnet.simtooreal_public.*.id
  security_groups = [aws_security_group.simtooreal_lb.id]
  idle_timeout    = 1800

  tags = {
    Description = "simtooreal Application Load Balancer managed by Terraform"
    Environment = "production"
  }
}

# target group for simtooreal backend
resource "aws_lb_target_group" "simtooreal_backend" {
  name        = "simtooreal-backend"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.simtooreal.id
  target_type = "ip"
  slow_start  = 60

  health_check {
    interval = 60
    timeout  = 10
    path     = "/"
    matcher  = "200"
  }

  tags = {
    Description = "simtooreal Application Load Balancer target group managed by Terraform"
    Environment = "production"
  }
}

# security group for simtooreal load balancer
resource "aws_security_group" "simtooreal_lb" {
  name        = "simtooreal_lb"
  description = "simtooreal load balancer security group managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  ingress {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 80
    to_port   = 80

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Redirect all traffic from the ALB to the target group
resource "aws_lb_listener" "simtooreal" {
  load_balancer_arn = aws_lb.simtooreal.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.simtooreal.arn

  default_action {
    target_group_arn = aws_lb_target_group.simtooreal_backend.id
    type             = "forward"
  }
}

# listener for http to be redirected to https
resource "aws_lb_listener" "simtooreal_http" {
  load_balancer_arn = aws_lb.simtooreal.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

### S3

# simtooreal s3 bucket
resource "aws_s3_bucket" "simtooreal_public" {
  bucket = "simtooreal-public"
  acl    = "private"

  tags = {
    Name        = "simtooreal"
    Environment = "production"
  }
}

# simtooreal s3 bucket
resource "aws_s3_bucket" "simtooreal_private" {
  bucket = "simtooreal-private"
  acl    = "private"

  tags = {
    Name        = "simtooreal"
    Environment = "production"
  }
}

# bastion
resource "aws_s3_bucket_object" "simtooreal_public" {
  bucket = aws_s3_bucket.simtooreal_public.bucket
  key    = "bastion.tar.gz"
  source = "bastion.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("bastion.tar.gz")
}

# tar-ed up simtooreal directory without terraform files
resource "aws_s3_bucket_object" "simtooreal_private" {
  bucket = aws_s3_bucket.simtooreal_private.bucket
  key    = "simtooreal.tar.gz"
  source = "simtooreal.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("simtooreal.tar.gz")
}

### Systems Manager

# ssm parameter group for database password
resource "aws_ssm_parameter" "db_password" {
  name        = "/parameter/production/POSTGRESQL_PASSWORD"
  description = "The database password"
  type        = "SecureString"
  value       = var.db_password
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "db_endpoint" {
  name        = "/parameter/production/POSTGRESQL_HOST"
  description = "The database endpoint"
  type        = "SecureString"
  value       = aws_rds_cluster.simtooreal.endpoint
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "openai_api_key" {
  name        = "/parameter/production/OPENAI_API_KEY"
  description = "Your OpenAI API Key"
  type        = "SecureString"
  value       = var.openai_api_key
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for user id password
resource "aws_ssm_parameter" "simtooreal_aws_access_key_id" {
  name        = "/parameter/production/AWS_ACCESS_KEY_ID"
  description = "The database password"
  type        = "SecureString"
  value       = var.aws_access_key_id
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for user secret endpoint
resource "aws_ssm_parameter" "simtooreal_secret_access_key" {
  name        = "/parameter/production/AWS_SECRET_ACCESS_KEY"
  description = "The database endpoint"
  type        = "SecureString"
  value       = var.aws_secret_access_key
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}


