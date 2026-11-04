# AWS EKS bootstrap — self-managed nodes only. Deliberately avoids:
#   - Managed node groups (locks you into AWS-specific lifecycle)
#   - Fargate (Fargate-only patterns don't translate to k3s/kind)
#   - Managed addons (we install our own ingress-nginx, cert-manager, etc.
#     in the platform module so the same tree applies on every target)
#
# Platform module then takes the kubeconfig output and runs unchanged.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws  = { source = "hashicorp/aws", version = "~> 5.0" }
    null = { source = "hashicorp/null", version = "~> 3.2" }
  }
}

provider "aws" {
  region = var.region
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.24"

  cluster_name    = var.cluster_name
  cluster_version = var.kubernetes_version

  vpc_id                   = var.vpc_id
  subnet_ids               = var.subnet_ids
  control_plane_subnet_ids = length(var.control_plane_subnet_ids) > 0 ? var.control_plane_subnet_ids : var.subnet_ids

  cluster_endpoint_public_access = true

  # No managed addons — platform module provides equivalents.
  cluster_addons = {}

  # Self-managed node groups only — explicit choice for portability.
  eks_managed_node_groups = {}
  fargate_profiles        = {}

  self_managed_node_groups = {
    workers = {
      name          = "workers"
      instance_type = var.instance_type
      min_size      = var.node_group_min
      max_size      = var.node_group_max
      desired_size  = var.node_group_desired
      ami_type      = "AL2023_x86_64_STANDARD"
      capacity_type = "ON_DEMAND"
    }
  }

  # IRSA enabled for IAM-roles-for-service-accounts when needed.
  enable_irsa = true

  tags = {
    "verifiably.io/managed-by" = "terraform"
    "verifiably.io/cluster"    = var.cluster_name
  }
}

# Render kubeconfig file — platform module reads from path.
locals {
  kubeconfig_path = "${abspath(var.kubeconfig_dir)}/${var.cluster_name}.kubeconfig"
}

resource "null_resource" "kubeconfig" {
  triggers = {
    cluster_name = var.cluster_name
    endpoint     = module.eks.cluster_endpoint
  }
  provisioner "local-exec" {
    # Terraform defaults local-exec to /bin/sh. On Debian/Ubuntu that is
    # dash, which has no `set -o pipefail` and aborts with "Illegal option".
    # macOS /bin/sh is bash, which is why this only failed in CI.
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      command -v aws >/dev/null || { echo "aws CLI not installed"; exit 127; }
      mkdir -p "${abspath(var.kubeconfig_dir)}"
      aws eks update-kubeconfig \
        --region ${var.region} \
        --name ${var.cluster_name} \
        --kubeconfig "${local.kubeconfig_path}" \
        --alias ${var.cluster_name}
    EOT
  }
  depends_on = [module.eks]
}
