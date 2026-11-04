# Local-kind bootstrap module.
#
# Creates a kind cluster (Docker-in-Docker style) with a MetalLB pool wired
# to the Docker network kind uses. After `terraform apply`, the cluster is
# fully functional for the platform module: ingress-nginx will get a real
# LoadBalancer IP, and the host can reach it via the extraPortMappings.
#
# Implementation note — null_resource + local-exec instead of the
# tehcyx/kind provider so this module has no chicken-and-egg with the
# helm/kubernetes providers (which would otherwise need a kubeconfig at
# init time, before the cluster exists).

terraform {
  required_version = ">= 1.6"
  required_providers {
    local = { source = "hashicorp/local", version = "~> 2.5" }
  }
}

locals {
  kubeconfig_path = "${abspath(var.kubeconfig_dir)}/${var.cluster_name}.kubeconfig"

  kind_config = yamlencode({
    kind       = "Cluster"
    apiVersion = "kind.x-k8s.io/v1alpha4"
    name       = var.cluster_name
    nodes = concat(
      [for i in range(var.control_plane_replicas) : {
        role = "control-plane"
        # Only the first control-plane gets the host port mappings — kind
        # rejects duplicate hostPorts, and ingress-nginx schedules to one
        # node anyway.
        extraPortMappings = i == 0 ? [
          { containerPort = 80, hostPort = var.host_http_port, protocol = "TCP" },
          { containerPort = 443, hostPort = var.host_https_port, protocol = "TCP" },
        ] : []
      }],
      [for i in range(var.worker_replicas) : { role = "worker" }],
    )
  })
}

resource "local_file" "kind_config" {
  filename        = "${path.module}/.tfstate/kind-config.yaml"
  content         = local.kind_config
  file_permission = "0644"
}

resource "null_resource" "kubeconfig_dir" {
  triggers = { dir = abspath(var.kubeconfig_dir) }
  provisioner "local-exec" {
    command = "mkdir -p ${abspath(var.kubeconfig_dir)}"
  }
}

# Cluster create — re-runs only when kind config or node image change.
resource "null_resource" "kind_cluster" {
  triggers = {
    cluster_name = var.cluster_name
    config_hash  = sha256(local.kind_config)
    node_image   = var.node_image
  }

  depends_on = [local_file.kind_config, null_resource.kubeconfig_dir]

  provisioner "local-exec" {
    # Terraform defaults local-exec to /bin/sh. On Debian/Ubuntu that is
    # dash, which has no `set -o pipefail` and aborts with "Illegal option".
    # macOS /bin/sh is bash, which is why this only failed in CI.
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      command -v kind   >/dev/null || { echo "kind not installed (brew install kind)"; exit 127; }
      command -v docker >/dev/null || { echo "docker not installed";                   exit 127; }
      docker info       >/dev/null || { echo "docker daemon not running";               exit 1;   }

      if kind get clusters | grep -qx "${self.triggers.cluster_name}"; then
        echo "kind cluster ${self.triggers.cluster_name} already exists — skipping create"
      else
        kind create cluster \
          --name "${self.triggers.cluster_name}" \
          --image "${self.triggers.node_image}" \
          --config "${local_file.kind_config.filename}" \
          --kubeconfig "${local.kubeconfig_path}"
      fi

      # Even if the cluster already existed, re-export the kubeconfig so
      # downstream resources have a guaranteed-fresh file.
      kind export kubeconfig --name "${self.triggers.cluster_name}" --kubeconfig "${local.kubeconfig_path}"
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "kind delete cluster --name '${self.triggers.cluster_name}' || true"
  }
}

# MetalLB install — controllers + IP pool. We use kubectl + helm via
# local-exec so this module is provider-free; the platform module (Phase
# 3.2) is where the real provider-driven Helm wiring lives.
resource "null_resource" "metallb" {
  triggers = {
    cluster_name = var.cluster_name
    pool_cidr    = var.metallb_pool_cidr
  }
  depends_on = [null_resource.kind_cluster]

  provisioner "local-exec" {
    # Terraform defaults local-exec to /bin/sh. On Debian/Ubuntu that is
    # dash, which has no `set -o pipefail` and aborts with "Illegal option".
    # macOS /bin/sh is bash, which is why this only failed in CI.
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      export KUBECONFIG="${local.kubeconfig_path}"

      command -v kubectl >/dev/null || { echo "kubectl not installed"; exit 127; }
      command -v helm    >/dev/null || { echo "helm not installed";    exit 127; }

      # Install MetalLB controllers via the official chart; pinned version.
      helm repo add metallb https://metallb.github.io/metallb >/dev/null 2>&1 || true
      helm repo update metallb >/dev/null
      helm upgrade --install metallb metallb/metallb \
        --namespace metallb-system \
        --create-namespace \
        --version 0.14.8 \
        --wait \
        --timeout 5m

      # Wait for the speaker DaemonSet + controller Deployment to be Ready
      # before applying the L2/IPAddressPool CRDs (otherwise the webhook
      # rejects them).
      kubectl -n metallb-system rollout status deploy/metallb-controller --timeout=180s
      kubectl -n metallb-system rollout status daemonset/metallb-speaker  --timeout=180s

      cat <<YAML | kubectl apply -f -
      apiVersion: metallb.io/v1beta1
      kind: IPAddressPool
      metadata:
        name: kind-pool
        namespace: metallb-system
      spec:
        addresses:
          - ${self.triggers.pool_cidr}
      ---
      apiVersion: metallb.io/v1beta1
      kind: L2Advertisement
      metadata:
        name: kind-l2
        namespace: metallb-system
      spec:
        ipAddressPools:
          - kind-pool
      YAML
    EOT
  }
}
