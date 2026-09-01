#!/usr/bin/env bash
# ec2-bootstrap.sh — cloud-init / user-data script for a single-host
# Ubuntu 24.04 LTS EC2 instance that will run the K8s waltid scenario via
# k8s-deploy.sh up waltid --target=ec2.
#
# Idempotent: safe to re-run (skips work that's already done). Logs to
# /var/log/cloud-init-output.log so you can SSH in and `tail -F` it.
#
# Sized for m6i.2xlarge (8 vCPU, 32 GiB RAM, 100 GiB gp3) but smaller
# instances will work for the install steps — only the deploy itself
# needs the resources.
#
# What this script installs:
#   - apt baseline: git curl ca-certificates gnupg jq unzip
#   - Docker CE (cosign image verify, GHA-style local checks, kind fallback)
#   - kubectl, helm, terraform, k6  (each via the project's official APT repo)
#   - kind                           (binary; only used by --target=local)
#   - k3s --disable=traefik,servicelb (the platform chart owns ingress + LB)
#   - GNU bash 5.x (Ubuntu 24.04 ships 5.2 — verified, not reinstalled)
#
# What this script configures:
#   - Kernel limits the Helm releases need:
#       fs.inotify.max_user_watches  = 524288
#       fs.inotify.max_user_instances = 512
#       vm.max_map_count              = 262144   # Loki / Elasticsearch family
#   - File descriptor + process limits in /etc/security/limits.d/
#   - ubuntu added to docker group
#   - /etc/rancher/k3s/k3s.yaml chmod 644 so deploy.sh + helm can read it
#
# Pre-pulls heavy umbrella-workload images into k3s containerd to halve
# the first deploy time. Platform-layer images (kube-prom, vault, etc.)
# are NOT pre-pulled — those are pulled on-demand via helm + are smaller.
#
# Final marker:
#   /var/lib/cloud/instance/k8s-bootstrap-complete   # bootstrap finished OK
#   /var/lib/cloud/instance/k8s-bootstrap-failed     # something exploded — see log

set -euo pipefail

LOG_PREFIX="[ec2-bootstrap]"
log() { echo "${LOG_PREFIX} $*"; }
fail() { echo "${LOG_PREFIX} FAIL: $*" >&2; touch /var/lib/cloud/instance/k8s-bootstrap-failed; exit 1; }
trap 'fail "interrupted at line $LINENO"' ERR

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------- 0. Sanity
[[ "$(id -u)" -eq 0 ]] || fail "must run as root (cloud-init user-data does)"
. /etc/os-release
[[ "$ID" == "ubuntu" ]] || log "WARNING: tested only on Ubuntu — yours: $ID $VERSION_ID"

# ---------------------------------------------------------------- 1. apt
log "[1/8] apt baseline"
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release \
  git jq unzip

# ---------------------------------------------------------------- 2. Docker
if ! command -v docker >/dev/null; then
  log "[2/8] docker"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
     https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  usermod -aG docker ubuntu || true
else
  log "[2/8] docker already present, skipping"
fi

# ---------------------------------------------------------------- 3. kubectl
if ! command -v kubectl >/dev/null; then
  log "[3/8] kubectl"
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key \
    | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /" \
    > /etc/apt/sources.list.d/kubernetes.list
  apt-get update -y
  apt-get install -y kubectl
else
  log "[3/8] kubectl already present, skipping"
fi

# ---------------------------------------------------------------- 4. helm
if ! command -v helm >/dev/null; then
  log "[4/8] helm"
  curl -fsSL https://baltocdn.com/helm/signing.asc \
    | gpg --dearmor -o /etc/apt/keyrings/helm.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" \
    > /etc/apt/sources.list.d/helm.list
  apt-get update -y
  apt-get install -y helm
else
  log "[4/8] helm already present, skipping"
fi

# ---------------------------------------------------------------- 5. terraform
if ! command -v terraform >/dev/null; then
  log "[5/8] terraform"
  curl -fsSL https://apt.releases.hashicorp.com/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/hashicorp.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/hashicorp.list
  apt-get update -y
  apt-get install -y terraform
else
  log "[5/8] terraform already present, skipping"
fi

# ---------------------------------------------------------------- 6. k6
if ! command -v k6 >/dev/null; then
  log "[6/8] k6"
  curl -fsSL https://dl.k6.io/key.gpg \
    | gpg --dearmor -o /etc/apt/keyrings/k6.gpg
  echo "deb [signed-by=/etc/apt/keyrings/k6.gpg] https://dl.k6.io/deb stable main" \
    > /etc/apt/sources.list.d/k6.list
  apt-get update -y
  apt-get install -y k6
else
  log "[6/8] k6 already present, skipping"
fi

# kind binary (fallback for local-target testing on the EC2 box itself).
if ! command -v kind >/dev/null; then
  log "[6.5/8] kind binary"
  arch=$(dpkg --print-architecture)
  case "$arch" in amd64) k_arch=amd64;; arm64) k_arch=arm64;; *) fail "unsupported arch: $arch";; esac
  curl -fsSL "https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-${k_arch}" -o /usr/local/bin/kind
  chmod +x /usr/local/bin/kind
fi

# ---------------------------------------------------------------- 7. Kernel
log "[7/8] kernel limits"
cat >/etc/sysctl.d/99-k8s-waltid.conf <<'EOF'
# Inotify watchers — kube-prometheus-stack, kyverno, argo-cd, vault all
# install many ConfigMaps/Secrets; default limits run out under load.
fs.inotify.max_user_watches  = 524288
fs.inotify.max_user_instances = 512
# Memory map count — Loki (BoltDB), Elasticsearch family. 262144 is the
# upstream-recommended floor.
vm.max_map_count = 262144
# Net: opening many in-cluster connections (envoy, prom, every Helm hook)
# blows past the default 4096 ephemeral port range on a single host.
net.ipv4.ip_local_port_range = 32768 65535
EOF
sysctl --system >/dev/null

cat >/etc/security/limits.d/99-k8s-waltid.conf <<'EOF'
*    soft  nofile  65536
*    hard  nofile  65536
*    soft  nproc   65536
*    hard  nproc   65536
root soft  nofile  65536
root hard  nofile  65536
EOF

# ---------------------------------------------------------------- 8. k3s
if ! systemctl is-active --quiet k3s; then
  log "[8/8] k3s install (--disable=traefik,servicelb)"
  # We disable traefik because the platform chart installs ingress-nginx,
  # and servicelb because we install MetalLB via the platform chart so
  # the same lb_mode=metallb wiring works on EKS / on-prem / EC2.
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable=traefik --disable=servicelb --write-kubeconfig-mode=644" sh -
  # Wait for kubeconfig + node Ready.
  for _ in $(seq 1 60); do
    [[ -f /etc/rancher/k3s/k3s.yaml ]] && break
    sleep 2
  done
  [[ -f /etc/rancher/k3s/k3s.yaml ]] || fail "k3s.yaml never appeared"
  for _ in $(seq 1 60); do
    /usr/local/bin/k3s kubectl get node | grep -q ' Ready ' && break
    sleep 2
  done
  /usr/local/bin/k3s kubectl get node | grep -q ' Ready ' || fail "k3s node never went Ready"
else
  log "[8/8] k3s already running, skipping"
fi

# ---------------------------------------------------------------- 9. Pre-pull
# Pull the heaviest umbrella-workload images directly into k3s's containerd
# so the first ./k8s-deploy.sh run doesn't have to fetch them through
# Helm. ~3-5 GiB of layers; takes 5-10 min depending on network.
log "[9/9] pre-pull umbrella workload images into k3s containerd"
PREPULL_IMAGES=(
  # walt.id services
  docker.io/waltid/issuer-api:0.23.1
  docker.io/waltid/verifier-api:0.23.1
  docker.io/waltid/wallet-api:0.23.1
  # IdPs
  docker.io/bitnami/keycloak:25.0.6-debian-12-r0
  docker.io/wso2/wso2is:7.0.0
  # Translation
  docker.io/libretranslate/libretranslate:v1.6.5
  # Postgres bundled with Bitnami keycloak
  docker.io/bitnami/postgresql:17.0.0-debian-12-r9
)
for img in "${PREPULL_IMAGES[@]}"; do
  log "  pulling $img"
  /usr/local/bin/k3s ctr images pull "$img" >/dev/null 2>&1 \
    || log "    (pull failed for $img — continuing; deploy.sh will retry on demand)"
done

# ---------------------------------------------------------------- Done
log "bootstrap complete"
touch /var/lib/cloud/instance/k8s-bootstrap-complete
log "next: SSH in as ubuntu, git clone the repo, then run:"
log "  ./deploy/k8s/scripts/k8s-deploy.sh up waltid --target=ec2"
