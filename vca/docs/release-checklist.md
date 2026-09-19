# Release checklist

This page lists what the release manager does before the first tag and
before every later tag.
[release.md](release.md) holds the tag steps and what the workflow
publishes.
This page holds the steps that no workflow can do.

## Before every tag

- [ ] `main` is green in `vca-ci`, and the last `vca-nightly` run passed.
- [ ] `cd vca && make lint && make test && make cover && make ste-lint`.
- [ ] `vca/hack/secret-scan.sh` prints no finding.
- [ ] `vca/hack/secret-scan-allow.txt` holds no entry, or each entry has an
      open issue with a date.
- [ ] The version follows SemVer 2.0.0, see [release.md](release.md).
- [ ] The Helm chart versions and the image tags match the git tag.
- [ ] `docs/spec-versions.md` names the specification versions of this
      release.

## Before the first tag: purge the secrets from the history

**Required. Purge the history before you tag `v1.0.0` (ADR-029 decision 6).**

The working tree holds no secret any more.
The git history still holds every one of them.
A clone of a public repository can read any object of that history.
A removal from the tree alone protects nothing.

### 1. Rotate first, purge second

Treat every value below as compromised, whatever the purge does:

| Secret | Where it was | What to do |
|---|---|---|
| Federation API keys | `verifiably-go/config/federation.json` | Issue a new key on each member deployment. |
| Inji Web keystore | `verifiably-go/deploy/compose/injiweb/config/certs/oidckeystore.p12` and `.../certs-runtime/` | Generate a new keystore per host and register the new certificate with eSignet. |
| walt.id wallet token key | the `tokenKey` chart default and `deploy/k8s/config/wallet/auth.conf` | Generate a key per deployment with `scripts/gen-demo-pki.sh`. Every wallet token signed with the old key stays forgeable. |
| WSO2 demo keystores | `verifiably-go/deploy/compose/stack/wso2-certs/` | Generate them per host with `scripts/gen-demo-pki.sh`. |
| CREDEBL seed password | `verifiably-go/deploy/compose/credebl/config/credebl-master-table.json` | Rewrite the seed so that it reads the password from the environment. Then remove the entry from `vca/hack/secret-scan-allow.txt`. |

### 2. Announce the rewrite

A history rewrite changes every commit hash after the first purged
object.
Every clone and every open branch must start again from the new history.

- [ ] Tell every contributor the date and the time of the rewrite.
- [ ] Merge or close every open pull request first.
- [ ] Note the current `HEAD` hash of each branch, so that you can compare.

### 3. Run git filter-repo

Install `git-filter-repo` first
([git-filter-repo](https://github.com/newren/git-filter-repo)).
Work on a fresh mirror clone, never on a working clone:

```sh
git clone --mirror https://github.com/centre-for-dpi/verifiably.git verifiably.git
cd verifiably.git
```

Remove the key stores and the loose copy:

```sh
git filter-repo --force \
  --path verifiably-go/deploy/compose/injiweb/config/certs/oidckeystore.p12 \
  --path verifiably-go/deploy/compose/injiweb/config/certs-runtime/oidckeystore.p12 \
  --path oidckeystore.p12 \
  --invert-paths
```

Remove every other private key and key store that the history holds:

```sh
git filter-repo --force \
  --path-glob 'verifiably-go/deploy/**/*.p12' \
  --path-glob 'verifiably-go/deploy/**/*.jks' \
  --path-glob 'verifiably-go/deploy/**/*.key' \
  --path-glob 'verifiably-go/deploy/**/*.pem' \
  --path verifiably-go/deploy/k8s/config/wallet/auth.conf \
  --path verifiably-go/config/trust-signing-key.pem \
  --invert-paths
```

Replace the secret values that live inside files that must stay.
Read the values out of the old history first.
This page does not repeat them:

```sh
git log -p --all -- verifiably-go/config/federation.json | grep -i apiKey | sort -u
git log -p --all -- verifiably-go/deploy/compose/credebl/config/credebl-master-table.json \
  | grep -i '"password"' | sort -u
```

Then write one rule per value:

```sh
cat > /tmp/replacements.txt <<'EOF'
<the first apiKey value>==>REPLACE_ME
<the second apiKey value>==>REPLACE_ME
<the CREDEBL password value>==>REPLACE_ME
regex:-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----==>REPLACE_ME
regex:-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----==>REPLACE_ME
EOF
git filter-repo --force --replace-text /tmp/replacements.txt
shred -u /tmp/replacements.txt
```

`git filter-repo` writes a report under `.git/filter-repo/`. Read it.

The operator must supply the CREDEBL platform admin password at bootstrap,
because the tracked seed file holds `REPLACE_ME`.

### 4. Check the new history

```sh
git log --oneline | head
git rev-list --objects --all | grep -i 'oidckeystore\|\.p12\|\.jks' || echo "no key store left"
git grep -I -n -E '"apiKey"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' $(git rev-list --all) \
  || echo "no API key left"
```

Clone the rewritten mirror into a normal clone and run the scan:

```sh
git clone verifiably.git verifiably-check
cd verifiably-check && vca/hack/secret-scan.sh
```

### 5. Publish the new history

- [ ] Take a backup of the old remote, for example a private mirror, and
      keep it offline.
- [ ] Push the rewritten history: `git push --force --mirror`.
- [ ] Ask GitHub Support to drop the cached objects of the old history.
      A force push alone leaves an unreachable object readable by its hash.
- [ ] Tell every contributor to re-clone. A rebase of an old clone brings
      the old objects back.
- [ ] Check the forks. A fork keeps its own copy of the old objects.

### 6. Then tag

- [ ] `vca/hack/secret-scan.sh` passes on the rewritten clone.
- [ ] The release notes record ADR-029 decision 6 as done.
- [ ] Tag `v1.0.0`, see [release.md](release.md).

## After the tag

- [ ] The release workflow published the images, the binaries, the charts,
      and the SBOM.
- [ ] `cosign verify` succeeds on one image.
- [ ] The release notes name the rotation steps that an operator must run.

## Reference

- ADR-029: the licence of the repository and the purge of the secrets.
- ADR-006: the release workflow and the version scheme.
- [release.md](release.md): the tag steps.
- [ci.md](ci.md): the merge gate and the secret scan.
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
