# Workloads module — pure glue. No business logic.
#
# Drops the umbrella waltid chart into namespace=var.namespace, then layers
# the ExternalSecret resources that pull walt.id DB credentials and signing
# keys from Vault. The platform module is responsible for installing the
# operators (CNPG, ESO, Vault) and for setting up the ClusterSecretStore;
# this module only declares the consumer-side bindings.

resource "kubernetes_namespace" "waltid" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      # Phase 7.2: restricted profile. WSO2IS is the most likely violator
      # — when it fails admission, override the wso2is chart's
      # podSecurityContext with the minimum needed concession (NEVER
      # downgrade the namespace label).
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}

resource "helm_release" "waltid" {
  name      = "waltid"
  chart     = var.umbrella_chart_path
  namespace = kubernetes_namespace.waltid.metadata[0].name

  # Always pass the deployment domain — the umbrella chart fans it out
  # into Ingress hostnames and walt.id baseUrls.
  set {
    name  = "global.domain"
    value = var.domain
  }
  set {
    name  = "global.clusterIssuer"
    value = var.lb_mode == "cloud" ? "letsencrypt" : "selfsigned"
  }

  # Keycloak is Bitnami's chart behind a thin wrapper, and it takes its Ingress
  # host as ingress.hostname -- it knows nothing about global.domain, which is
  # what every other chart here reads. The wrapper's values.yaml says the host
  # is "set to keycloak.<domain> by umbrella chart" and nothing ever set it, so
  # the release rendered an Ingress with no rules and an empty TLS host, which
  # helm emits happily and the API server rejects:
  #
  #   Ingress "waltid-keycloak" is invalid: spec: either `defaultBackend` or
  #   `rules` must be specified; spec.tls[0].hosts[0]: Invalid value: ""
  #
  # A values file cannot interpolate, so the domain has to be applied here,
  # where it is known.
  set {
    name  = "keycloak.keycloak.ingress.hostname"
    value = "keycloak.${var.domain}"
  }

  values = var.values_file != "" ? [file(var.values_file)] : []

  wait    = true
  timeout = 900

  dependency_update = true
}

# ClusterSecretStore — wires External Secrets Operator at Vault. The Vault
# Kubernetes auth role 'waltid' is bootstrapped by a separate Job (Phase
# 7.1); this resource fails-fast if that hasn't run yet, which is the
# desired ordering signal.
resource "kubectl_manifest" "vault_cluster_secret_store" {
  yaml_body = yamlencode({
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ClusterSecretStore"
    metadata   = { name = "vault-waltid" }
    spec = {
      provider = {
        vault = {
          server  = var.vault_address
          path    = "secret"
          version = "v2"
          auth = {
            kubernetes = {
              mountPath = "kubernetes"
              role      = "waltid"
              serviceAccountRef = {
                name      = "external-secrets"
                namespace = "external-secrets"
              }
            }
          }
        }
      }
    }
  })
  depends_on = [helm_release.waltid]
}

# ExternalSecret — wallet auth crypto. Vault path `secret/data/waltid/wallet/auth`
# is expected to hold keys: encryption-key, sign-key. Phase 7.1 also writes
# token-key as a Transit reference and this list grows to match.
resource "kubectl_manifest" "es_wallet_auth" {
  yaml_body = yamlencode({
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata   = { name = "wallet-auth", namespace = var.namespace }
    spec = {
      refreshInterval = "1h"
      secretStoreRef  = { kind = "ClusterSecretStore", name = "vault-waltid" }
      target = {
        name           = "wallet-auth"
        creationPolicy = "Owner"
      }
      data = [
        { secretKey = "WALLET_ENCRYPTION_KEY", remoteRef = { key = "waltid/wallet/auth", property = "encryption-key" } },
        { secretKey = "WALLET_SIGN_KEY", remoteRef = { key = "waltid/wallet/auth", property = "sign-key" } },
      ]
    }
  })
  depends_on = [kubectl_manifest.vault_cluster_secret_store]
}

# ExternalSecret — wallet DB credentials issued by CloudNativePG. CNPG
# writes a Secret in the cluster's namespace named '<cluster>-app'; ESO
# mirrors selected keys into ours. The actual cluster name is templated by
# the umbrella chart and exposed via a configmap (waltid-cnpg-info).
resource "kubectl_manifest" "es_wallet_db" {
  yaml_body = yamlencode({
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata   = { name = "wallet-db", namespace = var.namespace }
    spec = {
      refreshInterval = "1h"
      secretStoreRef  = { kind = "ClusterSecretStore", name = "vault-waltid" }
      target          = { name = "wallet-db", creationPolicy = "Owner" }
      data = [
        { secretKey = "DB_PASSWORD", remoteRef = { key = "waltid/wallet/db", property = "password" } },
      ]
    }
  })
  depends_on = [kubectl_manifest.vault_cluster_secret_store]
}
