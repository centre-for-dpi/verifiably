# On-prem k3s bootstrap. Shells out to k3sup against user-supplied node IPs.
# Output shape matches bootstrap/local-kind so the platform module is reused
# unchanged. MetalLB is NOT installed here — the platform module's
# helm_release.metallb handles it (gate via metallb_already_installed=false).

terraform {
  required_version = ">= 1.6"
  required_providers {
    null = { source = "hashicorp/null", version = "~> 3.2" }
  }
}

locals {
  servers         = [for n in var.nodes : n if n.role == "server"]
  agents          = [for n in var.nodes : n if n.role == "agent"]
  primary_server  = length(local.servers) > 0 ? local.servers[0] : null
  kubeconfig_path = "${abspath(var.kubeconfig_dir)}/${var.cluster_name}.kubeconfig"
}

resource "null_resource" "preflight" {
  triggers = { hash = sha1(jsonencode(var.nodes)) }
  provisioner "local-exec" {
    # Terraform defaults local-exec to /bin/sh. On Debian/Ubuntu that is
    # dash, which has no `set -o pipefail` and aborts with "Illegal option".
    # macOS /bin/sh is bash, which is why this only failed in CI.
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      command -v k3sup >/dev/null || { echo "k3sup not installed (https://github.com/alexellis/k3sup)"; exit 127; }
      [ -f "${var.ssh_key_path}" ] || { echo "ssh key not found at ${var.ssh_key_path}"; exit 1; }
      [ -n "${local.primary_server == null ? "" : local.primary_server.ip}" ] || { echo "no server node specified in var.nodes"; exit 2; }
      mkdir -p "${abspath(var.kubeconfig_dir)}"
    EOT
  }
}

# Install the primary control-plane.
resource "null_resource" "k3s_server_primary" {
  triggers = {
    cluster_name = var.cluster_name
    server_ip    = local.primary_server.ip
    version      = var.k3s_version
  }
  depends_on = [null_resource.preflight]

  provisioner "local-exec" {
    # Terraform defaults local-exec to /bin/sh. On Debian/Ubuntu that is
    # dash, which has no `set -o pipefail` and aborts with "Illegal option".
    # macOS /bin/sh is bash, which is why this only failed in CI.
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      k3sup install \
        --ip "${self.triggers.server_ip}" \
        --user "${var.ssh_user}" \
        --ssh-key "${var.ssh_key_path}" \
        --cluster \
        --k3s-version "${self.triggers.version}" \
        --k3s-extra-args '--disable=traefik --disable=servicelb' \
        --local-path "${local.kubeconfig_path}" \
        --context "${self.triggers.cluster_name}"
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "echo 'k3s teardown is left to the operator — destroy nodes manually'"
  }
}

# Join secondary servers (HA) and agents.
resource "null_resource" "k3s_join" {
  for_each = { for i, n in concat(slice(local.servers, 1, length(local.servers)), local.agents) : "${n.role}-${n.ip}" => n }
  triggers = {
    ip   = each.value.ip
    role = each.value.role
  }
  depends_on = [null_resource.k3s_server_primary]

  provisioner "local-exec" {
    # Terraform defaults local-exec to /bin/sh. On Debian/Ubuntu that is
    # dash, which has no `set -o pipefail` and aborts with "Illegal option".
    # macOS /bin/sh is bash, which is why this only failed in CI.
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      k3sup join \
        --ip "${self.triggers.ip}" \
        --user "${var.ssh_user}" \
        --ssh-key "${var.ssh_key_path}" \
        --server-ip "${local.primary_server.ip}" \
        --server-user "${var.ssh_user}" \
        --k3s-version "${var.k3s_version}" \
        ${self.triggers.role == "server" ? "--server" : ""}
    EOT
  }
}
