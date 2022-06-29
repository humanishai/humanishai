# route53 zone for humanish
data "aws_route53_zone" "zone_humanish" {
  name    = "humanish.io"
  private_zone = false
}

# route53 record for database so that no long database endpoints need to be remembered
resource "aws_route53_record" "record_database_humanish" {
  name    = "database.humanish.io"
  zone_id = data.aws_route53_zone.zone_humanish.id
  type    = "CNAME"
  ttl     = 30

  records = [aws_rds_cluster.humanish.endpoint]
}

# route53 record for private EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_private_humanish" {
  name    = "private.humanish.io"
  zone_id = data.aws_route53_zone.zone_humanish.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.humanish_private.private_ip]
}

# route53 record for public EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_public_humanish" {
  name    = "public.humanish.io"
  zone_id = data.aws_route53_zone.zone_humanish.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.humanish_public.public_ip]
}

# route53 record for short url
resource "aws_route53_record" "short_humanish" {
  name    = "humanish.io"
  zone_id = data.aws_route53_zone.zone_humanish.id
  type    = "A"

  alias {
    name                   = aws_lb.humanish.dns_name
    zone_id                = aws_lb.humanish.zone_id
    evaluate_target_health = true
  }
}

# route53 record for full url
resource "aws_route53_record" "humanish" {
  name    = "www.humanish.io"
  zone_id = data.aws_route53_zone.zone_humanish.id
  type    = "A"

  alias {
    name                   = aws_lb.humanish.dns_name
    zone_id                = aws_lb.humanish.zone_id
    evaluate_target_health = true
  }
}

# humanish certificate managed by Terraform
resource "aws_acm_certificate" "humanish" {
  domain_name       = "*.humanish.io"
  validation_method = "DNS"
  subject_alternative_names = ["humanish.io"]

  tags = {
    Description = "humanish certificate managed by Terraform"
    Name        = "humanish"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# the listener needs a cert as well
resource "aws_lb_listener_certificate" "humanish" {
  listener_arn    = aws_lb_listener.humanish.arn
  certificate_arn = aws_acm_certificate.humanish.arn
}

# validation record for humanish cert
resource "aws_route53_record" "humanish_validation" {
  name    = sort(aws_acm_certificate.humanish.domain_validation_options[*].resource_record_name)[0]
  type    = sort(aws_acm_certificate.humanish.domain_validation_options[*].resource_record_type)[0]
  records = [sort(aws_acm_certificate.humanish.domain_validation_options[*].resource_record_value)[0]]
  zone_id = data.aws_route53_zone.zone_humanish.id
  ttl     = "300"
}

# cert for humanish
resource "aws_acm_certificate_validation" "humanish" {
  certificate_arn         = aws_acm_certificate.humanish.arn
  validation_record_fqdns = [aws_route53_record.humanish_validation.fqdn]
}

### IAM/ECR

# ecr for holding all images
resource "aws_ecr_repository" "humanish" {
  name                 = "humanish"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ecr admin role for humanish
resource "aws_iam_user" "humanish_ecr_admin" {
  name = "humanish_ecr_admin"

  tags = {
    tag-key = "humanish"
  }
}

# ecr admin policy for humanish
resource "aws_iam_user_policy" "humanish_ecr_admin" {
  name = "humanish_ecr_admin"
  user = aws_iam_user.humanish_ecr_admin.name

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
resource "aws_iam_instance_profile" "humanish_s3_public_read" {
  name     = "humanish_s3_public_read"
}

resource "aws_iam_instance_profile" "humanish_s3_private_read" {
  name     = "humanish_s3_private_read"
}

# instance profile for ecs
resource "aws_iam_instance_profile" "humanish_ecs" {
  name     = "humanish_ecs"
}

# task execution ecs role for humanish
resource "aws_iam_role" "humanish_ecs_task_execution" {
  name = "humanish_ecs_task_execution"

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
resource "aws_iam_role" "humanish_s3_read" {
  name = "humanish_s3_read"

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
resource "aws_iam_role" "humanish_ecs" {
  name = "humanish_ecs"

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
resource "aws_iam_role_policy_attachment" "humanish_ecs_task_execution" {
  role       = aws_iam_role.humanish_ecs_task_execution.name
  policy_arn = aws_iam_policy.humanish_ecs_task_execution.arn
}

# ECS task  role policy attachment
resource "aws_iam_role_policy_attachment" "humanish_ecs" {
  role       = aws_iam_role.humanish_ecs.name
  policy_arn = aws_iam_policy.humanish_ecs.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "humanish_s3_public_read" {
  role       = aws_iam_role.humanish_s3_read.name
  policy_arn = aws_iam_policy.humanish_s3_public_read.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "humanish_s3_private_read" {
  role       = aws_iam_role.humanish_s3_read.name
  policy_arn = aws_iam_policy.humanish_s3_private_read.arn
}

# IAM policy for task execution
resource "aws_iam_policy" "humanish_ecs_task_execution" {
  name               = "humanish_ecs_task_execution"
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

# IAM policy for reading s3 in humanish
resource "aws_iam_policy" "humanish_s3_public_read" {
  name               = "humanish_s3_public_read"
  description        = "Policy to allow S3 reading of bucket humanish-public"

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
                "arn:aws:s3:::humanish-public/*",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_ACCESS_KEY_ID",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_SECRET_ACCESS_KEY",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/OPENAI_API_KEY"
            ]
        }
    ]
}
EOF
}

# IAM policy for reading s3 in humanish
resource "aws_iam_policy" "humanish_s3_private_read" {
  name               = "humanish_s3_private_read"
  description        = "Policy to allow S3 reading of bucket humanish-private and ssm"

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
                "arn:aws:s3:::humanish-private/*",
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
resource "aws_iam_policy" "humanish_ecs" {
  name               = "humanish_ecs"
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

# AWS VPC for humanish
resource "aws_vpc" "humanish" {
  cidr_block = "172.17.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
    Name        = "humanish"
  }
}

# Fetch Availability Zones in the current region
data "aws_availability_zones" "humanish" {
}

# Create var.az_count private subnets, each in a different AZ
resource "aws_subnet" "humanish_private" {
  count             = var.az_count
  cidr_block        = cidrsubnet(aws_vpc.humanish.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.humanish.names[count.index]
  vpc_id            = aws_vpc.humanish.id

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
  }
}

# Create var.az_count public subnets, each in a different AZ
resource "aws_subnet" "humanish_public" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.humanish.cidr_block,
    8,
    var.az_count + count.index,
  )
  availability_zone       = data.aws_availability_zones.humanish.names[count.index]
  vpc_id                  = aws_vpc.humanish.id
  map_public_ip_on_launch = true

  tags = {
    Description = "humanish public subnet managed by Terraform"
    Environment = "production"
  }
}

# Create var.az_count rds subnets, each in a different AZ
resource "aws_subnet" "humanish_rds" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.humanish.cidr_block,
    8,
    2 * var.az_count + 1 + count.index,
  )
  availability_zone = data.aws_availability_zones.humanish.names[count.index]
  vpc_id            = aws_vpc.humanish.id

  tags = {
    Description = "humanish RDS subnet managed by Terraform"
    Environment = "production"
  }
}

# IGW for the public subnet
resource "aws_internet_gateway" "humanish" {
  vpc_id = aws_vpc.humanish.id
}

# Route the public subnet traffic through the IGW
resource "aws_route" "humanish_internet_access" {
  route_table_id         = aws_vpc.humanish.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.humanish.id
}

# Create a NAT gateway with an EIP for each private subnet to get internet connectivity
resource "aws_eip" "humanish" {
  count      = var.az_count
  vpc        = true
  depends_on = [aws_internet_gateway.humanish]

  tags = {
    Description = "humanish gateway EIP managed by Terraform"
    Environment = "production"
  }
}

# NAT gateway for internet access
resource "aws_nat_gateway" "humanish" {
  count         = var.az_count
  subnet_id     = element(aws_subnet.humanish_public.*.id, count.index)
  allocation_id = element(aws_eip.humanish.*.id, count.index)

  tags = {
    Description = "humanish gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# Create a new route table for the private subnets
# And make it route non-local traffic through the NAT gateway to the internet
resource "aws_route_table" "humanish_private" {
  count  = var.az_count
  vpc_id = aws_vpc.humanish.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.humanish.*.id, count.index)
  }

  tags = {
    Description = "humanish gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# RDS route table for humanish
resource "aws_route_table" "humanish_rds" {
  count  = var.az_count
  vpc_id = aws_vpc.humanish.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.humanish.*.id, count.index)
  }

  tags = {
    Description = "humanish RDS route table managed by Terraform"
    Environment = "production"
  }
}

# Explicitely associate the newly created route tables to the private subnets (so they don't default to the main route table)
resource "aws_route_table_association" "humanish_private" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.humanish_private.*.id, count.index)
  route_table_id = element(aws_route_table.humanish_private.*.id, count.index)
}

resource "aws_route_table_association" "rhumanish_rds" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.humanish_rds.*.id, count.index)
  route_table_id = element(aws_route_table.humanish_rds.*.id, count.index)
}

### RDS

# subnet used by rds
resource "aws_db_subnet_group" "humanish" {
  name        = "humanish"
  description = "humanish RDS Subnet Group managed by Terraform"
  subnet_ids  = aws_subnet.humanish_rds.*.id
}

# Security Group for resources that want to access the database
resource "aws_security_group" "humanish_db_access" {
  vpc_id      = aws_vpc.humanish.id
  name        = "humanish_db_access"
  description = "humanish allow access to RDS, managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.humanish.cidr_block]
  }
}

# database security group
resource "aws_security_group" "humanish_rds" {
  name        = "humanish_rds"
  description = "humanish RDS security group, managed by Terraform"
  vpc_id      = aws_vpc.humanish.id

  //allow traffic for TCP 5432
  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.humanish_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# database cluster instances for humanish
resource "aws_rds_cluster_instance" "humanish" {
  # WARNING: Setting count to anything less than 2 reduces
  # the reliability of your system, many times an instance
  # failure has occured requiring a hot switch to a
  # secondary instance, if there is nothing to switch to
  # you may regret setting count to 1, consider reliability
  # and weigh it against infrastructure cost
  count                = 2
  cluster_identifier   = aws_rds_cluster.humanish.id
  instance_class       = "db.r4.large"
  db_subnet_group_name = aws_db_subnet_group.humanish.name
  engine               = "aurora-postgresql"
  engine_version       = "12.8"
}

# database cluster for humanish
resource "aws_rds_cluster" "humanish" {
  cluster_identifier        = "humanish"
  #availability_zones        = ["us-east-1a", "us-east-1b", "us-east-1c"]
  database_name             = "humanish"
  master_username           = "postgres"
  master_password           = var.db_password
  db_subnet_group_name      = aws_db_subnet_group.humanish.name
  engine                    = "aurora-postgresql"
  engine_version            = "12.8"
  vpc_security_group_ids    = [aws_security_group.humanish_rds.id]
  skip_final_snapshot       = "true"
  final_snapshot_identifier = "foo"
  storage_encrypted         = "true"
  #snapshot_identifier      = "humanish"
}

### Elasticache

# Security Group for resources that want to access redis
resource "aws_security_group" "humanish_redis_access" {
  vpc_id      = aws_vpc.humanish.id
  name        = "humanish_redis_access"
  description = "humanish redis access security group managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.humanish.cidr_block]
  }
}

resource "aws_security_group" "humanish_redis" {
  name        = "humanish_redis"
  vpc_id      = aws_vpc.humanish.id
  description = "humanish Redis Security Group managed by Terraform"

  //allow traffic for TCP 6379
  ingress {
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.humanish_ecs.*.id
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
resource "aws_security_group" "humanish_public" {
  name        = "humanish_public"
  description = "humanish public security group managed by Terraform"
  vpc_id      = aws_vpc.humanish.id

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

# # elasticache for humanish
# resource "aws_elasticache_subnet_group" "humanish" {
#   name       = "humanish"
#   subnet_ids = aws_subnet.humanish_private.*.id
# }

# # elasticache cluster for humanish
# resource "aws_elasticache_cluster" "humanish" {
#   cluster_id           = "humanish"
#   engine               = "redis"
#   node_type            = "cache.m5.large"
#   port                 = 6379
#   num_cache_nodes      = 1
#   security_group_ids   = [aws_security_group.humanish_redis.id]
#   subnet_group_name    = aws_elasticache_subnet_group.humanish.name
#   parameter_group_name = aws_elasticache_parameter_group.humanish.name
# }

# # elasticache parameter group for humanish
# resource "aws_elasticache_parameter_group" "humanish" {
#   name   = "redis-28-humanish"
#   family = "redis6.x"

#   parameter {
#     name  = "timeout"
#     value = "500"
#   }
# }

### AWS instances

resource "aws_key_pair" "humanish" {
  key_name   = "humanish"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC60teZFO7BuQVwHSUewqOFGo7Iko16pF/vpio8p0K4PR29KG4oaKd4lRHx0WwX5NlLTxEI5xXQWAN9sRQMz60UDnURKnGbjiy+QI/mL3Ivkt4YV6gEfGYdVChJE6bYpnmUbPn8e27JcIJkBcDEATTEZEvSWi8xNhXWOr3I4m/Jc7OOOZAk7R9roqFlsNQrOCizc543PxCLLKafwFcDNUg+h8EOO3+PVZJziAllRTx53WxYbOUZ1tSXwaiJkXSLhVmSZQU6gXuzjlUe2ZAYwW9XzQj8xvPjFJIgizJthnbFxiAn6BygM+/4YdT+SjdpG1Y3NamXgBPQPKWFX8vBkwxVIGywDqpMVlI8L1DgbU4ISVmkHj+kG8t7iX9NF73fG9M414SBpIZSO7lsXz5rHqoz7VZe5DDl5piVV/thXwaAMMm1kerF1GlWcvUxsABv4yD2DnuqMVPz77dP1abOVpRTr7NcSvQCFv4vcMO+0CAGO/RIn3vYawjLvBFEeICsd35mnWF+PDg4QiSycJpUX9wFnZKsbI+pOEfexHqseuiS+PTOgROVonC7PUzYjFbxT3SRKRsiJxNxmRtbaEjWXZpsEFjDb/ifs9K06mqTF6MqFYXVs4AhTxDuhqQ9EOBg/LG+JUIj76o4cl7VkUJxhYyP9MNO1Ze6AVl7/xmzigsEFQ== chase.brignac@example.com"
}

# public facing instance through which maintenance work is done
# t3a.micro has enough memory to run a Duo bastion but t3a.nano will save money
resource "aws_instance" "humanish_public" {
  ami                         = "ami-0fa37863afb290840"
  instance_type               = "t3a.micro"
  subnet_id                   = aws_subnet.humanish_public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.humanish_s3_public_read.name
  vpc_security_group_ids      = [aws_security_group.humanish_public.id]
  key_name                    = aws_key_pair.humanish.key_name
  depends_on                  = [aws_s3_bucket_object.humanish_public]
  user_data                   = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.humanish_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.humanish_secret_access_key.value}\necho $AWS_SECRET_ACCESS_KEY\necho $AWS_ACCESS_KEY_ID\nexport AWS_DEFAULT_REGION=us-east-1\nsudo apt-get update -y\nsudo apt-get install awscli -y\nsudo apt-get install awscli -y\naws s3 cp s3://humanish-public/bastion.tar.gz ./\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\ncurl -fsSL https://download.docker.com/linux/ubuntu/gpg  | apt-key add -\nadd-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable'\napt-get -y install docker-ce\nsystemctl start docker\napt-get install -y docker-compose\nsystemctl enable docker\ntar -zxvf bastion.tar.gz\ncd bastion/examples/compose\ndocker-compose up --build"
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
    Name = "humanish_public"
  }
}

# private instance inside the private subnet
# reaching RDS is done through this instance
resource "aws_instance" "humanish_private" {
  # These can be ecs optimized AMI if Amazon Linux OS is your thing
  # or you can even add an ECS compatible AMI, update instance type to t2.2xlarge
  # add to the user_data "ECS_CLUSTER= humanish >> /etc/ecs/ecs.config"
  # and add the iam_instance_profile of aws_iam_instance_profile.humanish_ecs.name
  # and you would then be able to use this instance in ECS
  ami           = "ami-0fa37863afb290840"
  instance_type = "t2.nano"
  subnet_id     = aws_subnet.humanish_private[0].id

  vpc_security_group_ids      = [aws_security_group.humanish_ecs.id]
  key_name                    = aws_key_pair.humanish.key_name
  iam_instance_profile        = aws_iam_instance_profile.humanish_s3_private_read.name
  depends_on                  = [aws_s3_bucket_object.humanish_private]
  user_data                   = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nsudo apt-get update -y\nsudo apt-get install awscli -y\necho $USER\necho ECS_CLUSTER=humanish > /etc/ecs/ecs.config\napt-add-repository --yes --update ppa:ansible/ansible\napt -y install ansible\napt install postgresql-client-common\napt-get -y install postgresql\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.humanish_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.humanish_secret_access_key.value}\nexport AWS_DEFAULT_REGION=us-east-1\naws s3 cp s3://humanish-private/humanish.tar.gz ./\ntar -zxvf humanish.tar.gz\nmv humanish data\napt install python3-pip -y\napt-get install tmux"
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
    Name = "humanish_private"
  }
}

### ECS

# ECS service for the backend
resource "aws_ecs_service" "humanish_backend" {
  name            = "humanish_backend"
  cluster         = aws_ecs_cluster.humanish.id
  task_definition = aws_ecs_task_definition.humanish_backend.family
  desired_count   = var.app_count
  launch_type     = "FARGATE"
  force_new_deployment = true

  network_configuration {
    security_groups = [aws_security_group.humanish_ecs.id]
    subnets         = aws_subnet.humanish_private.*.id
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.humanish_backend.id
    container_name   = "humanish-backend"
    container_port   = "8080"
  }

  depends_on = [aws_lb_listener.humanish]

  tags = {
    Description = "humanish Elastic Container Service managed by Terraform"
    Environment = "production"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# in case we ever want to start using reserved instances to try and save money
# resource "aws_ecs_service" "humanish_backend_reserved" {
#   name            = "humanish_backend_reserved"
#   cluster         = aws_ecs_cluster.humanish.id
#   task_definition = aws_ecs_task_definition.humanish_backend.arn
#   desired_count   = var.app_count
#   launch_type     = "EC2"
#
#   network_configuration {
#     security_groups = [aws_security_group.humanish_ecs.id]
#     subnets         = aws_subnet.humanish_private.*.id
#   }
#
#   load_balancer {
#     target_group_arn = aws_lb_target_group.humanish_backend.id
#     container_name   = "humanish_backend"
#     container_port   = "8080"
#   }
#
#   depends_on = [aws_lb_listener.humanish]
#
#   tags = {
#     Description = "humanish reserved Elastic Container Service managed by Terraform"
#     Environment = "production"
#   }
#
#   lifecycle {
#     ignore_changes = [desired_count]
#   }
# }

### Autoscaling

# autoscaling target for humanish
resource "aws_appautoscaling_target" "humanish_backend" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.humanish.name}/${aws_ecs_service.humanish_backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  max_capacity       = var.ecs_autoscale_max_instances
  min_capacity       = 1
}

resource "aws_cloudwatch_metric_alarm" "humanish_backend_memory_utilization_high" {
  alarm_name          = "humanish_backend_memory_utilization_high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 60

  dimensions = {
    ClusterName = aws_ecs_cluster.humanish.name
    ServiceName = aws_ecs_service.humanish_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.humanish_backend_memory_utilization_high.arn]
}

# memory metric alarm
resource "aws_cloudwatch_metric_alarm" "humanish_backend_memory_utilization_low" {
  alarm_name          = "humanish_backend_memory_utilization_high"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.humanish.name
    ServiceName = aws_ecs_service.humanish_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.humanish_backend_memory_utilization_low.arn]
}

# memory metric alarm
resource "aws_appautoscaling_policy" "humanish_backend_memory_utilization_high" {
  name               = "humanish_backend_memory_utilization_high"
  service_namespace  = aws_appautoscaling_target.humanish_backend.service_namespace
  resource_id        = aws_appautoscaling_target.humanish_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.humanish_backend.scalable_dimension

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
resource "aws_appautoscaling_policy" "humanish_backend_memory_utilization_low" {
  name               = "humanish_backend_memory_utilization_low"
  service_namespace  = aws_appautoscaling_target.humanish_backend.service_namespace
  resource_id        = aws_appautoscaling_target.humanish_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.humanish_backend.scalable_dimension

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
resource "aws_ecs_task_definition" "humanish_backend" {
  depends_on = [
    aws_lb.humanish,
    #aws_elasticache_cluster.humanish,
    aws_rds_cluster.humanish,
  ]
  family                   = "humanish"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024
  memory                   = 4096
  execution_role_arn       = aws_iam_role.humanish_ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "humanish-backend"
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
              "awslogs-group": "/ecs/humanish",
              "awslogs-region": "us-east-1",
              "awslogs-stream-prefix": "humanish-backend"
          }
      },
      "volumesFrom": [],
      "environment": []
    }
  ])
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "humanish" {
  name              = "/ecs/humanish"
  retention_in_days = 30

  tags = {
    Environment = "production"
    Application = "humanish"
  }
}

# This needs to be integrated completely into our container_definitions of our aws_ecs_task_definition
resource "aws_cloudwatch_log_stream" "humanish" {
  name           = "humanish"
  log_group_name = aws_cloudwatch_log_group.humanish.name
}

# ECS cluster for humanish
resource "aws_ecs_cluster" "humanish" {
  name = "humanish"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Traffic to the ECS Cluster should only come from the ALB, DB, or elasticache
resource "aws_security_group" "humanish_ecs" {
  name        = "humanish_ecs"
  description = "humanish Elastic Container Service (ECS) security group managed by Terraform"
  vpc_id      = aws_vpc.humanish.id

  ingress {
    protocol  = "tcp"
    from_port = "80"
    to_port   = "80"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.humanish_lb.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.humanish_lb.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "5432"
    to_port         = "5432"
    security_groups = [aws_security_group.humanish_db_access.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "6379"
    to_port         = "6379"
    security_groups = [aws_security_group.humanish_redis_access.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.humanish.cidr_block]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### ALB

# load balancer for humanish
resource "aws_lb" "humanish" {
  name            = "humanish"
  subnets         = aws_subnet.humanish_public.*.id
  security_groups = [aws_security_group.humanish_lb.id]
  idle_timeout    = 1800

  tags = {
    Description = "humanish Application Load Balancer managed by Terraform"
    Environment = "production"
  }
}

# target group for humanish backend
resource "aws_lb_target_group" "humanish_backend" {
  name        = "humanish-backend"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.humanish.id
  target_type = "ip"
  slow_start  = 60

  health_check {
    interval = 60
    timeout  = 10
    path     = "/"
    matcher  = "200"
  }

  tags = {
    Description = "humanish Application Load Balancer target group managed by Terraform"
    Environment = "production"
  }
}

# security group for humanish load balancer
resource "aws_security_group" "humanish_lb" {
  name        = "humanish_lb"
  description = "humanish load balancer security group managed by Terraform"
  vpc_id      = aws_vpc.humanish.id

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
resource "aws_lb_listener" "humanish" {
  load_balancer_arn = aws_lb.humanish.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.humanish.arn

  default_action {
    target_group_arn = aws_lb_target_group.humanish_backend.id
    type             = "forward"
  }
}

# listener for http to be redirected to https
resource "aws_lb_listener" "humanish_http" {
  load_balancer_arn = aws_lb.humanish.id
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

# humanish s3 bucket
resource "aws_s3_bucket" "humanish_public" {
  bucket = "humanish-public"
  acl    = "private"

  tags = {
    Name        = "humanish"
    Environment = "production"
  }
}

# humanish s3 bucket
resource "aws_s3_bucket" "humanish_private" {
  bucket = "humanish-private"
  acl    = "private"

  tags = {
    Name        = "humanish"
    Environment = "production"
  }
}

# bastion
resource "aws_s3_bucket_object" "humanish_public" {
  bucket = aws_s3_bucket.humanish_public.bucket
  key    = "bastion.tar.gz"
  source = "bastion.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("bastion.tar.gz")
}

# tar-ed up humanish directory without terraform files
resource "aws_s3_bucket_object" "humanish_private" {
  bucket = aws_s3_bucket.humanish_private.bucket
  key    = "humanish.tar.gz"
  source = "humanish.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("humanish.tar.gz")
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
    Name        = "humanish"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "db_endpoint" {
  name        = "/parameter/production/POSTGRESQL_HOST"
  description = "The database endpoint"
  type        = "SecureString"
  value       = aws_rds_cluster.humanish.endpoint
  overwrite   = "true"

  tags = {
    Name        = "humanish"
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
    Name        = "humanish"
    environment = "production"
  }
}

# ssm parameter group for user id password
resource "aws_ssm_parameter" "humanish_aws_access_key_id" {
  name        = "/parameter/production/AWS_ACCESS_KEY_ID"
  description = "The database password"
  type        = "SecureString"
  value       = var.aws_access_key_id
  overwrite   = "true"

  tags = {
    Name        = "humanish"
    environment = "production"
  }
}

# ssm parameter group for user secret endpoint
resource "aws_ssm_parameter" "humanish_secret_access_key" {
  name        = "/parameter/production/AWS_SECRET_ACCESS_KEY"
  description = "The database endpoint"
  type        = "SecureString"
  value       = var.aws_secret_access_key
  overwrite   = "true"

  tags = {
    Name        = "humanish"
    environment = "production"
  }
}


