# mDL Production Issuance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `verifiably-go` able to issue a conformant ISO 18013-5 mDL through the normal operator flow (pick DPG → pick/create schema → fill data → issue), by upgrading walt.id and routing `mso_mdoc` to `issuer-api2`.

**Architecture:** `verifiably-go` mediates; DPGs issue. Nothing here signs credentials inside the Go process. walt.id is upgraded 0.18.2 → 0.23.1, `issuer-api2` is deployed as a versioned service **alongside** (not replacing) the legacy `issuer-api`, and the existing `case "mso_mdoc"` in the walt.id adapter is repointed at it. Two cross-format improvements the upgrade unlocks — per-claim multi-language labels and an issuer display name — ride along because they fix defects affecting every credential the system issues.

**Tech Stack:** Go 1.x (stdlib `net/http`, `encoding/json`), HOCON config files, Docker Compose + Helm, Go html/template + htmx for the operator UI, walt.id Community Stack 0.23.1.

**Spec:** `docs/superpowers/specs/2026-08-21-mdl-production-issuance-design.md`

## Global Constraints

- **Branch dependency:** This work references `internal/mdl/doctype.go` and `internal/mdl/testdata/verify/verify.mjs`, which live on `feat/mdl-issuer` (PR #13, unmerged). **Task 0 resolves this.** Do not start Task 1 until Task 0 is done.
- **walt.id target version:** `0.23.1` exactly. Not `latest`, not `0.23.2` — `0.23.1` is the version whose source the analysis ADR diffed and against which the design's spike ran.
- **`issuer-api2` first exists at `0.21.0`.** Any version below that has no such module.
- **mdoc requires EC P-256 keys.** Both issuer and holder. Ed25519 is rejected with `The key type "kty" must be EC`.
- **`issuer-api2` must never be published externally.** No `ports:` in Compose, `ClusterIP` with no Ingress in Kubernetes. It has no authentication knob; network isolation is the entire mitigation for unauthenticated minting and `GET /issuer2/sessions` key leakage.
- **No private key material in versioned files.** HOCON env-var substitution only, matching existing configs.
- **English is the base language** for all labels. Locale codes are free-form strings (`es-DO`, `ht`, `qu`) — never validated against a fixed list.
- **Never change `SubjectData`'s `map[string]string` shape.** Portrait travels as base64 in a string; that is the established platform convention.
- Run `gofmt` and `go vet ./...` before every commit. The repo has no direct-push-to-main policy — all work lands via PR.

---

### Task 0: Resolve the branch dependency

**Files:**
- No file edits. Repository/branch operation only.

**Interfaces:**
- Consumes: nothing.
- Produces: a working branch that contains `verifiably-go/internal/mdl/doctype.go` and `verifiably-go/internal/mdl/testdata/verify/verify.mjs`. Every later task assumes these paths resolve.

- [ ] **Step 1: Confirm the current branch state**

```bash
cd verifiably
git fetch origin
git log --oneline -1 origin/main
gh pr view 13 --json state,mergeable,title
```

Expected: PR #13 shows `"state": "OPEN"`.

- [ ] **Step 2: Verify the two required files are absent from main and present on the feature branch**

```bash
git show origin/main:verifiably-go/internal/mdl/doctype.go >/dev/null 2>&1 \
  && echo "PRESENT on main" || echo "ABSENT from main (expected)"
git show origin/feat/mdl-issuer:verifiably-go/internal/mdl/doctype.go >/dev/null 2>&1 \
  && echo "PRESENT on feat/mdl-issuer (expected)" || echo "ABSENT — STOP, investigate"
```

Expected: `ABSENT from main (expected)` then `PRESENT on feat/mdl-issuer (expected)`.

- [ ] **Step 3: Ask the human which path to take**

Two options, and this is a judgement call the human owns:

- **(a) Merge PR #13 first.** Its 26 tests pass and an independent verifier accepts its output. Then branch this work from an updated `main`.
- **(b) Branch this work from `feat/mdl-issuer`.** Faster, but this PR then carries PR #13's diff too, making review larger.

Stop and ask. Do not pick unilaterally.

- [ ] **Step 4: Create the working branch from whichever base was chosen**

```bash
git checkout -b feat/mdl-production-issuance <chosen-base>
git log --oneline -1
```

- [ ] **Step 5: Verify the required files resolve on the new branch**

```bash
test -f verifiably-go/internal/mdl/doctype.go && echo "doctype.go OK"
test -f verifiably-go/internal/mdl/testdata/verify/verify.mjs && echo "verify.mjs OK"
```

Expected: both print OK. If not, stop — later tasks will fail.

---

### Task 1: Upgrade walt.id 0.18.2 → 0.23.1

**Files:**
- Modify: `verifiably-go/deploy/cloud/ec2-bootstrap.sh:193-195`
- Modify: `verifiably-go/deploy/compose/hub/.env.example:82`
- Modify: `verifiably-go/deploy/compose/hub/docker-compose.yml:141`
- Modify: `verifiably-go/deploy/compose/stack/docker-compose.yml:145,159,170`
- Modify: `verifiably-go/deploy/k8s/helm/charts/walt-issuer/Chart.yaml:6`
- Modify: `verifiably-go/deploy/k8s/helm/charts/walt-issuer/values.yaml:5`
- Modify: `verifiably-go/deploy/k8s/helm/charts/walt-verifier/Chart.yaml:6`
- Modify: `verifiably-go/deploy/k8s/helm/charts/walt-verifier/values.yaml:5`
- Modify: `verifiably-go/deploy/k8s/helm/charts/walt-wallet/Chart.yaml:6`
- Modify: `verifiably-go/deploy/k8s/helm/charts/walt-wallet/values.yaml:5`
- Modify: `verifiably-go/deploy/k8s/helm/umbrella/waltid/Chart.yaml:6`
- Modify: `verifiably-go/scripts/gen-backends.sh:73`
- Test: `verifiably-go/internal/adapters/waltid/integration_test.go:190` (and the comment at `:8`, `:58`)

**Interfaces:**
- Consumes: Task 0's working branch.
- Produces: a deployment pinned to walt.id `0.23.1` everywhere. Task 2 assumes `0.23.1` is the running version.

- [ ] **Step 1: Enumerate every executable pin so none is missed**

```bash
cd verifiably
grep -rn "0\.18\.2" --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.example" \
  verifiably-go/deploy verifiably-go/scripts | grep -v node_modules
```

Expected: 21 lines. Of these, **16 are executable pins** to change; 5 are prose comments inside `bootstrap-waltid-did.sh` (lines 5, 14, 186, 228) — leave those for Step 7.

- [ ] **Step 2: Update the integration test's image pin first, so it can prove the upgrade**

In `verifiably-go/internal/adapters/waltid/integration_test.go`, change line 190 from `"waltid/issuer-api:0.18.2"` to `"waltid/issuer-api:0.23.1"`, and update the comments at lines 8 and 58 that name the version.

- [ ] **Step 3: Run the integration test against the NEW image before changing anything else**

This is the whole safety net for this task. It does not run by default — it is behind `t.Skip` unless `WALTID_INTEGRATION=1`.

```bash
cd verifiably/verifiably-go
WALTID_INTEGRATION=1 go test ./internal/adapters/waltid/ -run TestIntegration -v 2>&1 | tail -40
```

Expected: PASS. Requires the `docker` CLI on PATH.

If it FAILS, stop and report the failure — do not proceed. A failure here means 0.23.1 breaks something the design's spike did not cover, and that is exactly what this step exists to catch.

- [ ] **Step 4: Commit the test change alone, so the safety net is recorded before the pins move**

```bash
cd verifiably
git add verifiably-go/internal/adapters/waltid/integration_test.go
git commit -m "test(waltid): point integration test at 0.23.1 before bumping deploy pins

Run with WALTID_INTEGRATION=1; it boots a real container and issues, so it
proves the upgrade rather than assuming it. Committed separately so the
safety net is in place before the deployment pins move."
```

- [ ] **Step 5: Update all 16 executable pins**

Replace `0.18.2` with `0.23.1` in each of the files listed under **Files** above. In `gen-backends.sh:73` the value is `"Version": "v0.18.2"` → `"Version": "v0.23.1"` (note the `v` prefix — this string is what the operator sees on the DPG card).

- [ ] **Step 6: Verify no executable pin was missed**

```bash
grep -rn "0\.18\.2" --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.example" \
  verifiably-go/deploy verifiably-go/scripts | grep -v node_modules
```

Expected: exactly 4 lines remain, all prose comments in `scripts/bootstrap-waltid-did.sh` (lines 5, 14, 186, 228).

- [ ] **Step 7: Update the stale prose comments in bootstrap-waltid-did.sh**

Those four comments describe behaviour verified against 0.18.2. The endpoint shapes they document (`/onboard/issuer` body, `/livez`) were confirmed unchanged in the analysis ADR, so only the version number is wrong. Change `0.18.2` → `0.23.1` in each.

Leave the ~80 documentation comments in Go files (`config.go`, `issuer.go`, `verifier.go`, `wallet.go`, `catalog.go`, `vctypes.go`, handlers) **unchanged** — they are recorded as debt in Task 9, because touching them would bloat this diff with no behavioural change.

- [ ] **Step 8: Verify the whole build and unit suite still pass**

```bash
cd verifiably/verifiably-go
gofmt -l . | grep -v vendor || echo "gofmt clean"
go vet ./... 2>&1 | tail -20
go test ./... 2>&1 | tail -30
```

Expected: gofmt clean, vet clean, all tests PASS.

- [ ] **Step 9: Commit**

```bash
cd verifiably
git add verifiably-go/deploy verifiably-go/scripts
git commit -m "chore(waltid): upgrade Community Stack 0.18.2 -> 0.23.1

Hard prerequisite for mDL: issuer-api2 does not exist as a module before
0.21.0, so a conformant mdoc cannot be issued at 0.18.2 at any config.

The risk that made this upgrade dangerous is cleared. The analysis ADR
flagged buildCredentialData's VCDM 1.1 @context mixed with VCDM 2.0
validFrom/validUntil as the one unverified item with system-wide blast
radius. The design spike issued those exact bodies against a real 0.23.1
across all four paths (jwt_vc_json with and without credentialStatus,
vc+sd-jwt, mso_mdoc): everything passes through verbatim, including
statusListIndex staying a string, and nbf/exp mapping correctly.

16 executable pins updated, including gen-backends.sh:73 which renders the
version string on the operator's DPG card. Go documentation comments citing
0.18.2 are deliberately left for a follow-up — see the plan's Task 9."
```

---

### Task 2: Deploy `issuer-api2` as an internal-only service

**Files:**
- Create: `verifiably-go/deploy/k8s/config/issuer2/issuer2-profiles.conf`
- Create: `verifiably-go/deploy/k8s/config/issuer2/_features.conf`
- Create: `verifiably-go/deploy/k8s/config/issuer2/issuer-service.conf`
- Modify: `verifiably-go/deploy/compose/stack/docker-compose.yml` (new service after `issuer-api`, which ends at line 157)
- Modify: `verifiably-go/deploy/compose/hub/.env.example`

**Interfaces:**
- Consumes: Task 1's `0.23.1` pin.
- Produces: a service reachable at `http://issuer-api2:7002` **from inside the compose network only**, serving profiles `isoMdl` and `isoPhotoId` with emptied sample data. Task 3 posts to `/issuer2/credential-offers` there.

- [ ] **Step 1: Extract the shipped configs as the starting point**

Do not write these from scratch — the image ships working ones.

```bash
cd verifiably
mkdir -p verifiably-go/deploy/k8s/config/issuer2
docker create --name i2extract waltid/issuer-api2:0.23.1
docker cp i2extract:/waltid-issuer-api2/config/issuer2-profiles.conf \
  verifiably-go/deploy/k8s/config/issuer2/issuer2-profiles.conf
docker cp i2extract:/waltid-issuer-api2/config/_features.conf \
  verifiably-go/deploy/k8s/config/issuer2/_features.conf
docker cp i2extract:/waltid-issuer-api2/config/issuer-service.conf \
  verifiably-go/deploy/k8s/config/issuer2/issuer-service.conf
docker rm i2extract
```

- [ ] **Step 2: Confirm what was extracted**

```bash
grep -n "isoMdl = {" verifiably-go/deploy/k8s/config/issuer2/issuer2-profiles.conf
grep -n "isoPhotoId = {" verifiably-go/deploy/k8s/config/issuer2/issuer2-profiles.conf
grep -n "persistence" verifiably-go/deploy/k8s/config/issuer2/_features.conf
```

Expected: `isoMdl` around line 389, `isoPhotoId` around line 632, and `# persistence,` appearing **commented out**. That comment is the silent-fallback trap.

- [ ] **Step 3: Strip every profile except the two in scope**

Delete all profile blocks except `jwk` (the shared key definition at the top, referenced as `${defaultIssuerKey}`), `isoMdl`, and `isoPhotoId`.

Reason beyond tidiness: `listProfiles()` validates **every** profile on every call, so one malformed profile breaks the whole catalog. Fewer profiles is less surface for that failure.

- [ ] **Step 4: Empty the sample applicant data — safety-critical**

In `isoMdl` and `isoPhotoId`, replace every value inside `credentialData` with an empty string, empty array, or `0` as the type requires. Keep the **keys**, and keep the entire `mDocNameSpacesDataMappingConfig` block exactly as shipped.

Why: `runtimeOverrides` merges recursively for objects and replaces for scalars, so any field the caller does not send **keeps the profile's value**. The shipped profile is a fictional Austrian person — `family_name = "Musterfrau"`, `given_name = "Anna Maria"`, `issuing_country = "AT"`. Left as-is, forgetting one field silently issues a real credential carrying another person's data.

For `driving_privileges`, keep `arrayConfig` and its object entries — that block declares *types*, not data.

- [ ] **Step 5: Replace the published example key with env substitution**

Find the `jwk` block defining `defaultIssuerKey` and replace the inline private key with:

```hocon
jwk = {
  type = "jwk"
  jwk = ${VERIFIABLY_ISSUER2_KEY}
}
```

The shipped value is a private key published in walt.id's public repository — one of the two hard security blockers. It must not survive into a versioned file.

The key must be **EC P-256**; mdoc rejects Ed25519.

- [ ] **Step 6: Resolve the persistence flag explicitly**

Edit `_features.conf`. Either uncomment `persistence` and configure Redis in `persistence.conf`, or leave it off **and add a comment stating in-memory is deliberate for a single-pod deployment**, noting that in-flight offers and pre-authorized codes are lost on restart (already-issued credentials are unaffected — they are signed artifacts already in the wallet).

What is unacceptable is ambiguity: a Redis config with the flag off is silently ignored and the service runs in memory anyway, with no error.

- [ ] **Step 7: Add the service to the stack compose file**

Insert after the `issuer-api` service definition:

```yaml
  # issuer-api2 runs ALONGSIDE issuer-api, not instead of it. Only mso_mdoc
  # routes here — it is the sole walt.id service that can type CBOR (via
  # mDocNameSpacesDataMappingConfig), which mdoc requires. Every other format
  # stays on the legacy issuer-api, which keeps operator-defined custom
  # schemas working (issuer-api2 demands pre-provisioned profiles).
  #
  # Deliberately NO ports: — issuer-api2 ships no authentication knob, so
  # POST /issuer2/credential-offers would let anyone reachable mint a signed
  # credential with arbitrary subject data, and GET /issuer2/sessions returns
  # issuerKey private material. Network isolation IS the mitigation.
  issuer-api2:
    image: waltid/issuer-api2:0.23.1
    restart: unless-stopped
    depends_on:
      - caddy
    environment:
      SERVICE_HOST: ${VERIFIABLY_PUBLIC_HOST:-localhost}
      ISSUER_API_PORT: 7002
      VERIFIABLY_ISSUER2_KEY: ${VERIFIABLY_ISSUER2_KEY:?issuer-api2 requires an EC P-256 issuer key}
    volumes:
      - ../../k8s/config/issuer2:/waltid-issuer-api2/config:ro
```

The `:?` form makes compose refuse to start with a clear message when the key is unset, instead of booting with walt.id's published example key.

- [ ] **Step 8: Document the new env var**

Append to `.env.example`, matching the existing `VERIFIABLY_TRUST_SIGNING_KEY` entry's style:

```bash
# EC P-256 issuer key for issuer-api2 (mdoc/mDL issuance), as a JWK JSON object.
# mdoc REQUIRES EC — Ed25519 is rejected with: The key type "kty" must be EC
# Generate:
#   openssl ecparam -name prime256v1 -genkey -noout -out issuer2-key.pem
#   # then convert the PEM to a JWK object and paste it here
# Never commit the value. walt.id's shipped default is a private key published
# in their public repo and must not be used for anything real.
VERIFIABLY_ISSUER2_KEY=
```

- [ ] **Step 9: Boot the service and verify both profiles load**

```bash
cd verifiably/verifiably-go/deploy/compose/stack
docker compose up -d issuer-api2
sleep 20
docker compose logs issuer-api2 --tail 20
```

Expected: `Web server ready!` with no profile-validation exception.

- [ ] **Step 10: Verify it is NOT reachable from outside the network**

```bash
curl -s -m 5 -o /dev/null -w "from host: %{http_code}\n" http://localhost:7002/issuer2/sessions \
  || echo "unreachable from host (correct)"
```

Expected: unreachable, or a connection error. If the host reaches it, a `ports:` entry leaked in — fix before continuing. This is the entire security mitigation.

- [ ] **Step 11: Commit**

```bash
cd verifiably
git add verifiably-go/deploy/k8s/config/issuer2 \
        verifiably-go/deploy/compose/stack/docker-compose.yml \
        verifiably-go/deploy/compose/hub/.env.example
git commit -m "feat(deploy): add issuer-api2 as an internal-only service

Runs alongside the legacy issuer-api rather than replacing it. issuer-api2 is
the only walt.id service that can type CBOR, which mdoc requires; but it
cannot host the other formats, because it demands pre-provisioned profiles
and so loses the operator-defined custom schemas SaveCustomSchema supports
today on the legacy path.

Security posture is network isolation, not configuration: issuer-api2 ships
no auth knob, so POST /issuer2/credential-offers would let anyone reachable
mint a signed credential with arbitrary subject data, and GET /issuer2/sessions
returns issuerKey private material. No ports are published.

Profiles trimmed to isoMdl and isoPhotoId with their sample applicant data
emptied. That is safety-critical: runtimeOverrides merges recursively, so any
field a caller omits keeps the profile value — and the shipped sample is a
fictional Austrian person. Emptied, a forgotten field comes out blank rather
than silently carrying someone else's nationality.

The published example issuer key is replaced with HOCON env substitution,
required at boot so a missing key fails loudly instead of falling back to
walt.id's public keypair."
```

---

### Task 3: Route `mso_mdoc` to `issuer-api2` in the adapter

**Files:**
- Modify: `verifiably-go/internal/adapters/waltid/config.go:25-48` (add `Issuer2BaseURL`)
- Modify: `verifiably-go/internal/adapters/waltid/adapter.go:68-85` (build the second client)
- Create: `verifiably-go/internal/adapters/waltid/issuer2.go`
- Modify: `verifiably-go/internal/adapters/waltid/issuer.go:679-693` (the `case "mso_mdoc"`)
- Test: `verifiably-go/internal/adapters/waltid/issuer2_test.go`

**Interfaces:**
- Consumes: Task 2's service at `http://issuer-api2:7002`.
- Produces:
  - `Config.Issuer2BaseURL string` with JSON tag `issuer2BaseUrl`
  - `(*Adapter).issuer2 *httpx.Client` — nil when unconfigured
  - `func buildIssuer2Offer(schema vctypes.Schema, subject map[string]string) (issuer2OfferRequest, error)`
  - `type issuer2OfferRequest struct` with fields `ProfileID string`, `AuthMethod string`, `ExpiresInSeconds int`, `RuntimeOverrides *issuer2RuntimeOverrides`
  - `type issuer2OfferResponse struct` with fields `OfferID string`, `CredentialOffer string`
  - `func profileIDForDocType(docType string) (string, bool)`

- [ ] **Step 1: Write the failing test for profile resolution**

Create `verifiably-go/internal/adapters/waltid/issuer2_test.go`:

```go
package waltid

import "testing"

func TestProfileIDForDocType(t *testing.T) {
	tests := []struct {
		docType string
		want    string
		wantOK  bool
	}{
		{"org.iso.18013.5.1.mDL", "isoMdl", true},
		{"org.iso.23220.photoID.1", "isoPhotoId", true},
		{"org.iso.7367.1.mVRC", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := profileIDForDocType(tt.docType)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("profileIDForDocType(%q) = (%q, %v), want (%q, %v)",
				tt.docType, got, ok, tt.want, tt.wantOK)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run TestProfileIDForDocType -v
```

Expected: FAIL — `undefined: profileIDForDocType`.

- [ ] **Step 3: Write the minimal implementation**

Create `verifiably-go/internal/adapters/waltid/issuer2.go`:

```go
package waltid

// issuer-api2 is a SEPARATE walt.id service from the legacy issuer-api, used
// only for mso_mdoc. It is the only walt.id issuer that can type CBOR (via
// mDocNameSpacesDataMappingConfig), which ISO 18013-5 requires: without it
// birth_date serialises as text instead of tag 1004 and portrait as text
// instead of a byte string, and no conformant reader accepts the result.
//
// Every other format stays on the legacy issuer-api — issuer-api2 demands
// pre-provisioned profiles and so cannot host the operator-defined custom
// schemas SaveCustomSchema supports today.

// docTypeProfiles maps an ISO docType onto the issuer-api2 profileId that
// issues it. Only docTypes with a profile versioned in
// deploy/k8s/config/issuer2/issuer2-profiles.conf appear here: issuer-api2
// rejects a profileId it cannot resolve, so an unlisted docType must fail
// early with a clear message rather than at issuance time.
var docTypeProfiles = map[string]string{
	"org.iso.18013.5.1.mDL":   "isoMdl",
	"org.iso.23220.photoID.1": "isoPhotoId",
}

// profileIDForDocType resolves an ISO docType to its issuer-api2 profileId.
func profileIDForDocType(docType string) (string, bool) {
	id, ok := docTypeProfiles[docType]
	return id, ok
}
```

- [ ] **Step 4: Run the test and confirm it passes**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run TestProfileIDForDocType -v
```

Expected: PASS.

- [ ] **Step 5: Write the failing test for the merge trap — the most important test here**

Append to `issuer2_test.go`:

```go
import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// A field the caller omits must NOT appear in the request at all. issuer-api2
// merges runtimeOverrides recursively over the profile, so any key we send
// wins but any key we omit keeps the profile's value. The versioned profile
// has its sample data emptied precisely so an omission surfaces as blank —
// but if we were to send a key with a zero value we would be asserting that
// blank on purpose, and if we send nothing the profile decides. This test
// pins the boundary: only what the operator actually filled in gets sent.
func TestBuildIssuer2OfferOmitsUnsetFields(t *testing.T) {
	schema := vctypes.Schema{
		ID:   "org.iso.18013.5.1.mDL",
		Std:  "mso_mdoc",
		Name: "Driver's Licence",
	}
	subject := map[string]string{
		"family_name": "Perez",
		"given_name":  "Ana",
	}

	req, err := buildIssuer2Offer(schema, subject)
	if err != nil {
		t.Fatalf("buildIssuer2Offer: %v", err)
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "Perez") || !strings.Contains(body, "Ana") {
		t.Errorf("supplied fields missing from request: %s", body)
	}
	for _, absent := range []string{"nationality", "issuing_country", "birth_date"} {
		if strings.Contains(body, absent) {
			t.Errorf("unsupplied field %q leaked into request — it would inherit the profile's sample value: %s", absent, body)
		}
	}
	if req.ProfileID != "isoMdl" {
		t.Errorf("ProfileID = %q, want isoMdl", req.ProfileID)
	}
	if req.AuthMethod != "PRE_AUTHORIZED" {
		t.Errorf("AuthMethod = %q, want PRE_AUTHORIZED", req.AuthMethod)
	}
}
```

- [ ] **Step 6: Run it and confirm it fails**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run TestBuildIssuer2OfferOmitsUnsetFields -v
```

Expected: FAIL — `undefined: buildIssuer2Offer`.

- [ ] **Step 7: Implement the request builder**

Append to `issuer2.go`:

```go
import (
	"fmt"

	"github.com/verifiably/verifiably-go/vctypes"
)

// issuer2OfferRequest is the POST /issuer2/credential-offers body. Its shape
// differs from the legacy issuer-api's IssuanceRequest entirely: profileId +
// runtimeOverrides, not credentialConfigurationId + mdocData.
type issuer2OfferRequest struct {
	ProfileID        string                   `json:"profileId"`
	AuthMethod       string                   `json:"authMethod"`
	ExpiresInSeconds int                      `json:"expiresInSeconds,omitempty"`
	RuntimeOverrides *issuer2RuntimeOverrides `json:"runtimeOverrides,omitempty"`
}

type issuer2RuntimeOverrides struct {
	// CredentialData is namespace-keyed, exactly like the legacy mdocData:
	// {"<namespace>": {"<field>": "<value>"}}.
	CredentialData map[string]map[string]string `json:"credentialData,omitempty"`
}

// issuer2OfferResponse is the 201 body. The legacy issuer-api returns the
// offer URI as a bare text/plain string; issuer-api2 returns JSON, so the
// caller must parse rather than trim.
type issuer2OfferResponse struct {
	OfferID         string `json:"offerId"`
	CredentialOffer string `json:"credentialOffer"`
}

// issuer2OfferTTL bounds how long the citizen has to scan the offer.
const issuer2OfferTTL = 300

// buildIssuer2Offer turns a schema plus the operator's filled-in fields into
// a credential-offer request.
//
// Only fields the operator actually supplied are sent. This is deliberate and
// load-bearing: issuer-api2 deep-merges runtimeOverrides over the profile, so
// an omitted field keeps whatever the profile holds. Our versioned profile has
// its sample data emptied for exactly this reason (see
// deploy/k8s/config/issuer2/issuer2-profiles.conf) — walt.id's shipped default
// is a fictional Austrian person, and inheriting it silently would issue a
// real credential carrying someone else's data.
func buildIssuer2Offer(schema vctypes.Schema, subject map[string]string) (issuer2OfferRequest, error) {
	docType := mdocDocTypeFor(schema)
	profileID, ok := profileIDForDocType(docType)
	if !ok {
		return issuer2OfferRequest{}, fmt.Errorf(
			"waltid: no issuer-api2 profile for docType %q — only pre-provisioned docTypes can be issued (see deploy/k8s/config/issuer2/issuer2-profiles.conf)",
			docType)
	}

	namespace := mdocNamespaceFor(docType)
	data := make(map[string]string, len(subject))
	for k, v := range subject {
		if v == "" {
			continue // omit rather than assert a blank
		}
		data[k] = v
	}

	req := issuer2OfferRequest{
		ProfileID:        profileID,
		AuthMethod:       "PRE_AUTHORIZED",
		ExpiresInSeconds: issuer2OfferTTL,
	}
	if len(data) > 0 {
		req.RuntimeOverrides = &issuer2RuntimeOverrides{
			CredentialData: map[string]map[string]string{namespace: data},
		}
	}
	return req, nil
}
```

- [ ] **Step 8: Extract the docType and namespace derivation into shared helpers**

`buildMdocData` (`issuer.go:1033-1048`) derives both inline. Two callers now need the same logic, so extract it rather than duplicate — a second copy would drift.

The existing inline code is:

```go
	doctype := schema.BaseType()
	if doctype == "" {
		doctype = schema.ID
	}
	namespace := doctype
	if i := strings.LastIndex(doctype, "."); i > 0 {
		namespace = doctype[:i]
	}
```

Add to `issuer2.go`:

```go
// mdocDocTypeFor resolves a schema's ISO docType. BaseType() carries it for
// stock catalog entries; custom schemas fall back to the ID.
func mdocDocTypeFor(schema vctypes.Schema) string {
	if dt := schema.BaseType(); dt != "" {
		return dt
	}
	return schema.ID
}

// mdocNamespaceFor derives the namespace from a docType by stripping the last
// dot-segment: org.iso.18013.5.1.mDL -> org.iso.18013.5.1.
func mdocNamespaceFor(docType string) string {
	if i := strings.LastIndex(docType, "."); i > 0 {
		return docType[:i]
	}
	return docType
}
```

Then replace the inline block in `buildMdocData` with:

```go
	doctype := mdocDocTypeFor(schema)
	namespace := mdocNamespaceFor(doctype)
```

- [ ] **Step 8b: Pin the extraction with a test so refactoring cannot change behaviour**

Append to `issuer2_test.go`:

```go
func TestMdocNamespaceFor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"org.iso.18013.5.1.mDL", "org.iso.18013.5.1"},
		{"org.iso.23220.photoID.1", "org.iso.23220.photoID"},
		{"nodots", "nodots"},
	}
	for _, tt := range tests {
		if got := mdocNamespaceFor(tt.in); got != tt.want {
			t.Errorf("mdocNamespaceFor(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
```

Note what the second case reveals: `org.iso.23220.photoID.1` strips to `org.iso.23220.photoID`, but the Photo ID profile's real base namespace is `org.iso.23220.1`. **Last-segment stripping does not hold for Photo ID.** Handle it explicitly in `docTypeProfiles` rather than by string surgery — extend the map to carry the namespace:

```go
type mdocProfile struct {
	profileID     string
	baseNamespace string
}

var docTypeProfiles = map[string]mdocProfile{
	"org.iso.18013.5.1.mDL":   {"isoMdl", "org.iso.18013.5.1"},
	"org.iso.23220.photoID.1": {"isoPhotoId", "org.iso.23220.1"},
}
```

Update `profileIDForDocType` to return the struct, and `buildIssuer2Offer` to take the namespace from it instead of calling `mdocNamespaceFor`. Keep `mdocNamespaceFor` for `buildMdocData`'s legacy path, which only ever sees mDL.

Adjust `TestProfileIDForDocType` from Step 1 accordingly — it must assert on the struct's fields.

- [ ] **Step 9: Run both tests and confirm they pass**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run "TestProfileIDForDocType|TestBuildIssuer2OfferOmitsUnsetFields" -v
```

Expected: both PASS.

- [ ] **Step 10: Commit the pure builder before wiring transport**

```bash
cd verifiably
git add verifiably-go/internal/adapters/waltid/issuer2.go \
        verifiably-go/internal/adapters/waltid/issuer2_test.go
git commit -m "feat(waltid): add issuer-api2 offer request builder

Pure functions only — no transport yet, so the merge semantics can be
pinned by tests before anything talks to the network.

The omission test is the important one. issuer-api2 deep-merges
runtimeOverrides over the profile, so a field the operator did not fill in
keeps the profile's value rather than coming out blank. Our versioned
profile has its sample data emptied for that reason, and this test pins the
other half: only fields actually supplied are sent, so a blank never
silently becomes walt.id's fictional Austrian sample data.

docTypeProfiles is an allowlist, not a lookup with a fallback: issuer-api2
rejects an unresolvable profileId, so an unlisted docType fails early with a
message naming the config file, instead of at issuance time in front of a
citizen."
```

- [ ] **Step 11: Add the config field**

In `verifiably-go/internal/adapters/waltid/config.go`, inside the `Config` struct (after `IssuerBaseURL`, line 26):

```go
	// Issuer2BaseURL points at the walt.id issuer-api2 service, used ONLY for
	// mso_mdoc. Empty disables mdoc issuance with a clear error rather than
	// silently falling back to the legacy issuer-api, which cannot type CBOR
	// and would emit a credential no conformant reader accepts.
	Issuer2BaseURL string `json:"issuer2BaseUrl"`
```

- [ ] **Step 12: Build the second HTTP client**

In `verifiably-go/internal/adapters/waltid/adapter.go`, add the field to the `Adapter` struct next to `issuer`:

```go
	issuer2  *httpx.Client
```

And in `New`, next to the existing `a.issuer = httpx.New(cfg.IssuerBaseURL)` guard (line 81):

```go
	if cfg.Issuer2BaseURL != "" {
		a.issuer2 = httpx.New(cfg.Issuer2BaseURL)
	}
```

- [ ] **Step 13: Repoint the `mso_mdoc` case**

Replace the body of `case "mso_mdoc":` in `issuer.go` (lines 679-693) so it returns early via issuer-api2 instead of populating `ir.MdocData`:

```go
	case "mso_mdoc":
		// mdoc goes to issuer-api2, NOT the legacy issuer-api this function
		// otherwise targets. The legacy service cannot type CBOR at any
		// version (mDocNameSpacesDataMappingConfig is absent through 0.23.1),
		// so it would emit birth_date as text instead of tag 1004 and
		// portrait as text instead of a byte string — a credential no
		// conformant reader accepts.
		//
		// This returns directly rather than falling through to the shared
		// POST below, because issuer-api2 takes a different request shape
		// AND returns JSON where the legacy returns bare text.
		return a.issueMdocViaIssuer2(ctx, req)
```

- [ ] **Step 14: Write the transport function**

Append to `issuer2.go`:

```go
import (
	"context"
	"encoding/json"

	"github.com/verifiably/verifiably-go/backend"
)

// issueMdocViaIssuer2 posts a credential offer to issuer-api2 and adapts its
// JSON response to the same IssueToWalletResult the legacy path returns, so
// callers cannot tell which service issued.
func (a *Adapter) issueMdocViaIssuer2(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	if a.issuer2 == nil {
		return backend.IssueToWalletResult{}, fmt.Errorf(
			"waltid: mso_mdoc requires issuer-api2 but issuer2BaseUrl is not configured — the legacy issuer-api cannot type CBOR and would emit a non-conformant credential")
	}

	offerReq, err := buildIssuer2Offer(req.Schema, req.SubjectData)
	if err != nil {
		return backend.IssueToWalletResult{}, err
	}

	raw, err := a.issuer2.DoRaw(ctx, "POST", "/issuer2/credential-offers",
		jsonReader(offerReq), "application/json", nil)
	if err != nil {
		// Surface issuer-api2's own message verbatim. A malformed profile
		// breaks its whole catalog, so the service's wording is more useful
		// to whoever debugs this than anything we could substitute.
		return backend.IssueToWalletResult{}, fmt.Errorf("waltid issuer-api2: %w", err)
	}

	var resp issuer2OfferResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return backend.IssueToWalletResult{}, fmt.Errorf(
			"waltid issuer-api2: parse offer response: %w (body: %.200s)", err, string(raw))
	}
	if resp.CredentialOffer == "" {
		return backend.IssueToWalletResult{}, fmt.Errorf(
			"waltid issuer-api2: response carried no credentialOffer (body: %.200s)", string(raw))
	}

	return backend.IssueToWalletResult{
		OfferURI: resp.CredentialOffer,
		OfferID:  resp.OfferID,
		Flow:     req.Flow,
	}, nil
}
```

- [ ] **Step 15: Write the response-parsing test**

Append to `issuer2_test.go`:

```go
func TestIssuer2OfferResponseParsing(t *testing.T) {
	// issuer-api2 returns JSON; the legacy issuer-api returns a bare string.
	// Parsing the wrong one yields an offer URI of "" and a QR that opens
	// nothing, so pin the shape.
	body := []byte(`{"offerId":"abc-123","profileId":"isoMdl","credentialOffer":"openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.org%2Foffer%3Fid%3Dabc-123"}`)

	var resp issuer2OfferResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OfferID != "abc-123" {
		t.Errorf("OfferID = %q, want abc-123", resp.OfferID)
	}
	if !strings.HasPrefix(resp.CredentialOffer, "openid-credential-offer://") {
		t.Errorf("CredentialOffer = %q, want an openid-credential-offer:// URI", resp.CredentialOffer)
	}
}
```

- [ ] **Step 16: Run the full package suite**

```bash
cd verifiably/verifiably-go
gofmt -l internal/adapters/waltid/
go vet ./internal/adapters/waltid/
go test ./internal/adapters/waltid/ -v 2>&1 | tail -30
```

Expected: gofmt silent, vet clean, all tests PASS — including the pre-existing ones, which must not regress.

- [ ] **Step 17: Wire the URL into the deployment config**

Add `issuer2BaseUrl` to the walt.id backend entry wherever `issuerBaseUrl` is set for the stack (check `scripts/gen-backends.sh` and any `backends*.json` that carries walt.id config):

```bash
cd verifiably
grep -rn "issuerBaseUrl" verifiably-go/scripts verifiably-go/config verifiably-go/deploy 2>/dev/null | grep -v node_modules
```

Set it to `http://issuer-api2:7002` — the compose service name, since the service is not published externally.

- [ ] **Step 18: Commit**

```bash
cd verifiably
git add verifiably-go/internal/adapters/waltid/ verifiably-go/scripts verifiably-go/config
git commit -m "feat(waltid): issue mso_mdoc through issuer-api2

The case existed already and bifurcated by format; it now returns early
through a second HTTP client instead of populating the legacy request. Two
things forced a separate path rather than a URL swap: issuer-api2 takes
profileId + runtimeOverrides where the legacy takes credentialConfigurationId
+ mdocData, and it returns JSON where the legacy returns a bare text offer URI.

Unconfigured issuer2BaseUrl fails with an explicit message rather than
falling back to the legacy service. Falling back would look like it worked
and emit a credential no conformant reader accepts — the failure would
surface at verification time, far from the cause.

Errors from issuer-api2 propagate verbatim. A malformed profile breaks that
service's entire catalog, so its own wording is more useful to whoever
debugs it than anything we would substitute."
```

---

### Task 4: Add multi-language labels to the field model

**Files:**
- Modify: `verifiably-go/vctypes/vctypes.go:347-352` (extend `FieldSpec`)
- Test: `verifiably-go/vctypes/fieldspec_label_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `FieldSpec.Labels map[string]string` — locale code → label. Free-form keys.
  - `func (f FieldSpec) Label(locale string) string` — resolves with fallback chain, never returns empty.
  - `func DeriveLabel(identifier string) string` — `family_name` → `Family Name`.

- [ ] **Step 1: Write the failing test**

Create `verifiably-go/vctypes/fieldspec_label_test.go`:

```go
package vctypes

import "testing"

func TestDeriveLabel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"family_name", "Family Name"},
		{"given_name", "Given Name"},
		{"age_over_18", "Age Over 18"},
		{"portrait", "Portrait"},
		{"un_distinguishing_sign", "Un Distinguishing Sign"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := DeriveLabel(tt.in); got != tt.want {
			t.Errorf("DeriveLabel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFieldSpecLabelResolution(t *testing.T) {
	f := FieldSpec{
		Name: "family_name",
		Labels: map[string]string{
			"en":    "Family Name",
			"es-DO": "Apellidos",
		},
	}

	if got := f.Label("es-DO"); got != "Apellidos" {
		t.Errorf("exact locale: got %q, want Apellidos", got)
	}
	if got := f.Label("en"); got != "Family Name" {
		t.Errorf("base locale: got %q, want Family Name", got)
	}
	// An unknown locale falls back to English rather than showing nothing.
	if got := f.Label("ht"); got != "Family Name" {
		t.Errorf("unknown locale should fall back to en: got %q", got)
	}
}

func TestFieldSpecLabelFallsBackToDerived(t *testing.T) {
	// No labels at all — today's behaviour must be preserved: the wallet
	// derives a label from the identifier, so we derive the same thing.
	f := FieldSpec{Name: "document_number"}
	if got := f.Label("es-DO"); got != "Document Number" {
		t.Errorf("no labels: got %q, want Document Number", got)
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd verifiably/verifiably-go
go test ./vctypes/ -run "TestDeriveLabel|TestFieldSpecLabel" -v
```

Expected: FAIL — `undefined: DeriveLabel`, `unknown field Labels`.

- [ ] **Step 3: Extend FieldSpec and implement the helpers**

In `verifiably-go/vctypes/vctypes.go`, extend the struct at line 347:

```go
type FieldSpec struct {
	Name     string
	Datatype string // "string" | "number" | "integer" | "boolean"
	Format   string // optional: "date" | "uri" | ...
	Required bool

	// Labels maps a locale code to this field's human-readable name, e.g.
	// {"en": "Family Name", "es-DO": "Apellidos"}. Locale codes are free-form
	// strings, deliberately not validated against a fixed list — OID4VCI
	// leaves the vocabulary open, and a deployment may need a language no
	// predefined list would carry.
	//
	// "en" is the base language: Label() falls back to it for any locale not
	// present. Empty Labels is valid and means "derive from Name", which is
	// what wallets do today anyway.
	Labels map[string]string
}
```

Append to the same file:

```go
// DeriveLabel turns a snake_case identifier into a human-readable label:
// family_name -> "Family Name". This mirrors what wallets already do when an
// issuer publishes no display metadata, so a field with no Labels renders
// identically to today rather than blank.
func DeriveLabel(identifier string) string {
	if identifier == "" {
		return ""
	}
	parts := strings.Split(identifier, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// Label resolves this field's display name for a locale, in order: exact
// match, then English (the base language), then derived from the identifier.
// It never returns empty for a field with a Name.
func (f FieldSpec) Label(locale string) string {
	if v, ok := f.Labels[locale]; ok && v != "" {
		return v
	}
	if v, ok := f.Labels["en"]; ok && v != "" {
		return v
	}
	return DeriveLabel(f.Name)
}
```

Confirm `strings` is imported in that file; add it if not.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
cd verifiably/verifiably-go
go test ./vctypes/ -run "TestDeriveLabel|TestFieldSpecLabel" -v
```

Expected: all PASS.

- [ ] **Step 5: Verify nothing else broke — FieldSpec is used widely**

```bash
cd verifiably/verifiably-go
go build ./... && go test ./... 2>&1 | tail -20
```

Expected: builds, all tests PASS. Adding a field is additive, but confirm rather than assume.

- [ ] **Step 6: Commit**

```bash
cd verifiably
git add verifiably-go/vctypes/
git commit -m "feat(vctypes): add per-field multi-language labels

FieldSpec gains Labels (locale -> name) plus Label() to resolve with an
exact / English / derived fallback chain.

Locale codes are free-form on purpose. OID4VCI leaves the vocabulary open
and a deployment may need a language no predefined list carries, so
validating against one would be an arbitrary restriction on a mechanism the
standard deliberately left open.

English is the base language, not Spanish: this is not a single-country
implementation.

Empty Labels stays valid and derives from the identifier — the same thing
wallets do today when an issuer publishes no display metadata, so existing
schemas render exactly as before."
```

---

### Task 5: Emit per-claim display in the walt.id catalog

**Files:**
- Modify: `verifiably-go/internal/adapters/waltid/catalog.go` (all four builders: `buildLinkedDataEntry` ~207, `buildSDJWTEntry` ~255, `buildMDocEntry` ~302, and the W3C builder)
- Test: `verifiably-go/internal/adapters/waltid/catalog_labels_test.go`

**Interfaces:**
- Consumes: `FieldSpec.Labels` and `FieldSpec.Label(locale)` from Task 4.
- Produces: HOCON catalog entries carrying a `claims` block with per-locale `display`, and a credential-level `display` array with one entry per configured locale instead of a single hardcoded `en-US`.

- [ ] **Step 1: Confirm the current hardcoded state**

```bash
cd verifiably/verifiably-go
grep -n 'locale = "en-US"' internal/adapters/waltid/catalog.go
```

Expected: exactly 4 occurrences — one per builder. Each is a single-entry `display` array at credential level, with no `claims` block at all.

- [ ] **Step 2: Write the failing test**

Create `verifiably-go/internal/adapters/waltid/catalog_labels_test.go`:

```go
package waltid

import (
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

func TestBuildClaimsBlockEmitsPerLocaleDisplay(t *testing.T) {
	fields := []vctypes.FieldSpec{
		{
			Name:   "family_name",
			Labels: map[string]string{"en": "Family Name", "es-DO": "Apellidos"},
		},
		{Name: "document_number"}, // no labels — must derive
	}

	got := buildClaimsBlock(fields)

	for _, want := range []string{
		"family_name",
		`name = "Family Name"`,
		`locale = "en"`,
		`name = "Apellidos"`,
		`locale = "es-DO"`,
		"document_number",
		`name = "Document Number"`, // derived, not blank
	} {
		if !strings.Contains(got, want) {
			t.Errorf("claims block missing %q:\n%s", want, got)
		}
	}
}

func TestBuildClaimsBlockEmptyForNoFields(t *testing.T) {
	// Stock (non-custom) schemas carry no FieldsSpec. They must emit no
	// claims block at all rather than an empty one, which walt.id's HOCON
	// parser would reject.
	if got := buildClaimsBlock(nil); got != "" {
		t.Errorf("expected empty string for no fields, got:\n%s", got)
	}
}
```

- [ ] **Step 3: Run it and confirm it fails**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run TestBuildClaimsBlock -v
```

Expected: FAIL — `undefined: buildClaimsBlock`.

- [ ] **Step 4: Implement the claims block builder**

Append to `verifiably-go/internal/adapters/waltid/catalog.go`:

```go
// buildClaimsBlock renders the OID4VCI `claims` metadata for a schema's
// fields, with one display entry per configured locale.
//
// This is the mechanism that lets a wallet show "Apellidos" to a
// Spanish-speaking holder instead of the raw identifier. Without it, wallets
// derive a label from the identifier themselves — which is why cdpi-wallet
// shows "Family Name" today regardless of the holder's language.
//
// Returns "" for a schema with no declared fields (stock catalog entries):
// an empty claims block is not valid HOCON here, and omitting it preserves
// exactly today's behaviour for those schemas.
func buildClaimsBlock(fields []vctypes.FieldSpec) string {
	if len(fields) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("        claims = [\n")
	for _, f := range fields {
		if f.Name == "" {
			continue
		}
		b.WriteString("            {\n")
		fmt.Fprintf(&b, "                path = [\"%s\"]\n", hoconEscape(f.Name))
		b.WriteString("                display = [\n")

		locales := claimLocales(f)
		for _, loc := range locales {
			fmt.Fprintf(&b,
				"                    { name = \"%s\", locale = \"%s\" }\n",
				hoconEscape(f.Label(loc)), hoconEscape(loc))
		}
		b.WriteString("                ]\n")
		b.WriteString("            }\n")
	}
	b.WriteString("        ]\n")
	return b.String()
}

// claimLocales returns the locales to emit for a field, English first and the
// rest sorted so catalog output is deterministic (the file is diffed and
// written on every schema save). A field with no labels yields just "en",
// whose Label() derives from the identifier.
func claimLocales(f vctypes.FieldSpec) []string {
	if len(f.Labels) == 0 {
		return []string{"en"}
	}
	out := make([]string, 0, len(f.Labels))
	hasEn := false
	for loc := range f.Labels {
		if loc == "en" {
			hasEn = true
			continue
		}
		out = append(out, loc)
	}
	sort.Strings(out)
	if hasEn || true { // English is always emitted: it is the base language
		out = append([]string{"en"}, out...)
	}
	return out
}
```

Confirm `sort`, `strings`, and `fmt` are imported in `catalog.go`.

- [ ] **Step 5: Run the tests and confirm they pass**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run TestBuildClaimsBlock -v
```

Expected: both PASS.

- [ ] **Step 6: Wire the claims block into all four builders**

In each of `buildLinkedDataEntry`, `buildSDJWTEntry`, `buildMDocEntry`, and the W3C builder, insert `buildClaimsBlock(schema.FieldsSpec)` into the emitted HOCON, immediately after the credential-level `display` array.

Each builder currently ends its format string with a `display = [...]` block followed by `    }`. Add the claims output between them, passing the rendered string as a new `%s` argument.

- [ ] **Step 7: Verify existing catalog tests still pass**

```bash
cd verifiably/verifiably-go
go test ./internal/adapters/waltid/ -run TestBuild -v 2>&1 | tail -25
```

Expected: PASS. `catalog_test.go` asserts on generated HOCON, so if its assertions are exact-match they may need updating for the new block — update the expectation, do not weaken the assertion.

- [ ] **Step 8: Verify the generated HOCON actually parses**

A malformed catalog entry is rejected at walt.id boot, and unit tests on string output cannot catch that. `integration_test.go` exists precisely to prove walt.id's HOCON parser accepts what we generate (see its comment at line 50).

```bash
cd verifiably/verifiably-go
WALTID_INTEGRATION=1 go test ./internal/adapters/waltid/ -run TestIntegration -v 2>&1 | tail -30
```

Expected: PASS. If HOCON is malformed, this is where it surfaces.

- [ ] **Step 9: Commit**

```bash
cd verifiably
git add verifiably-go/internal/adapters/waltid/
git commit -m "feat(waltid): emit per-claim display metadata with real locales

All four catalog builders wrote a single credential-level display entry
hardcoded to en-US, and no claims block at all. Every credential this system
issues therefore told any wallet in the world that its only language was US
English, and gave wallets nothing to render field names from — which is why
cdpi-wallet shows 'Family Name' derived from the identifier regardless of
the holder's language.

Schemas with no declared fields emit no claims block, preserving today's
behaviour exactly for stock catalog entries. Fields with no labels emit
English derived from the identifier — the same string wallets already
derive, so nothing regresses.

Verified through the integration test rather than only string assertions:
malformed HOCON is rejected at walt.id boot, which unit tests on generated
text cannot catch."
```

---

### Task 6: Add the label column to the schema builder UI

**Files:**
- Modify: `verifiably-go/templates/pages/issuer_schema_builder.html:156-190` (the `_field_row` template)
- Modify: `verifiably-go/internal/handlers/schema.go` (the form parser that reads `field_name_N` etc.)
- Test: `verifiably-go/internal/handlers/schema_labels_test.go`

**Interfaces:**
- Consumes: `FieldSpec.Labels` from Task 4.
- Produces: form fields `field_label_N` (English) and `field_label_N_<locale>` (additional), parsed into `FieldSpec.Labels`.

- [ ] **Step 1: Read the existing parser to confirm its shape**

```bash
cd verifiably/verifiably-go
sed -n '722,742p' internal/handlers/schema.go
```

The field loop lives inline inside the builder-data function and reads from `*http.Request` via `r.FormValue`, not from a standalone `parseFieldSpecs(url.Values)`. It caps at 50 rows and breaks when a row is absent. Label parsing goes inside that same loop.

- [ ] **Step 2: Extract the loop into a testable function**

The current loop cannot be unit-tested without constructing an `*http.Request`. Extract it first, unchanged in behaviour, so the label work lands on something testable:

```go
// parseFieldSpecsFromForm reads the indexed field rows (field_name_0,
// field_datatype_0, field_required_0, ...) the schema builder submits.
// Takes url.Values rather than *http.Request so it can be tested directly.
func parseFieldSpecsFromForm(form url.Values) []vctypes.FieldSpec {
	var out []vctypes.FieldSpec
	for i := 0; i < 50; i++ {
		name := form.Get(fmt.Sprintf("field_name_%d", i))
		dt := form.Get(fmt.Sprintf("field_datatype_%d", i))
		if dt == "" && name == "" && form[fmt.Sprintf("field_name_%d", i)] == nil {
			break
		}
		req := form.Get(fmt.Sprintf("field_required_%d", i)) == "on"
		if dt == "" {
			dt = "string"
		}
		f := vctypes.FieldSpec{Name: strings.TrimSpace(name), Datatype: dt, Required: req}
		if strings.Contains(dt, ":") {
			parts := strings.SplitN(dt, ":", 2)
			f.Datatype = parts[0]
			f.Format = parts[1]
		}
		out = append(out, f)
	}
	return out
}
```

Replace the inline loop in the builder-data function with `d.Fields = parseFieldSpecsFromForm(r.Form)`.

Note: the original reads `r.FormValue`, which parses the form on demand; `r.Form` requires `r.ParseForm()` to have run. Confirm the enclosing handler already calls it — if not, add `_ = r.ParseForm()` before the call.

- [ ] **Step 3: Verify the extraction changed nothing**

```bash
cd verifiably/verifiably-go
go build ./... && go test ./internal/handlers/ 2>&1 | tail -15
```

Expected: builds and existing tests PASS. This is a pure refactor; commit it separately:

```bash
cd verifiably
git add verifiably-go/internal/handlers/schema.go
git commit -m "refactor(handlers): extract schema-builder field parsing

Takes url.Values instead of *http.Request so the next commit's label parsing
can be unit-tested without constructing a request. No behaviour change."
```

- [ ] **Step 4: Write the failing test**

Create `verifiably-go/internal/handlers/schema_labels_test.go`:

```go
package handlers

import (
	"net/url"
	"testing"
)

func TestParseFieldLabelsFromForm(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "Family Name")
	form.Set("field_label_0_es-DO", "Apellidos")
	form.Set("field_label_0_ht", "Siyati")
	form.Set("field_name_1", "document_number")
	form.Set("field_datatype_1", "string")
	// field 1 deliberately has no label — must stay empty so Label() derives

	fields := parseFieldSpecsFromForm(form)

	if len(fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(fields))
	}
	if got := fields[0].Labels["en"]; got != "Family Name" {
		t.Errorf("en label = %q, want Family Name", got)
	}
	if got := fields[0].Labels["es-DO"]; got != "Apellidos" {
		t.Errorf("es-DO label = %q, want Apellidos", got)
	}
	if got := fields[0].Labels["ht"]; got != "Siyati" {
		t.Errorf("ht label = %q, want Siyati", got)
	}
	if len(fields[1].Labels) != 0 {
		t.Errorf("field with no label should have empty Labels, got %v", fields[1].Labels)
	}
}
```

- [ ] **Step 5: Run it and confirm it fails**

```bash
cd verifiably/verifiably-go
go test ./internal/handlers/ -run TestParseFieldLabelsFromForm -v
```

Expected: FAIL — labels are nil, since nothing populates them yet.

- [ ] **Step 6: Implement label parsing**

Inside `parseFieldSpecsFromForm`, after the datatype handling and before `out = append(...)`:

```go
		// Labels: field_label_N is English (the base language);
		// field_label_N_<locale> adds others. Locale codes are free-form —
		// whatever the operator typed — so we discover them by prefix scan
		// rather than checking against a fixed list.
		labels := map[string]string{}
		if en := strings.TrimSpace(form.Get(fmt.Sprintf("field_label_%d", i))); en != "" {
			labels["en"] = en
		}
		prefix := fmt.Sprintf("field_label_%d_", i)
		for key, vals := range form {
			if !strings.HasPrefix(key, prefix) || len(vals) == 0 {
				continue
			}
			loc := strings.TrimPrefix(key, prefix)
			if v := strings.TrimSpace(vals[0]); loc != "" && v != "" {
				labels[loc] = v
			}
		}
		if len(labels) > 0 {
			spec.Labels = labels
		}
```

- [ ] **Step 7: Run the test and confirm it passes**

```bash
cd verifiably/verifiably-go
go test ./internal/handlers/ -run TestParseFieldLabelsFromForm -v
```

Expected: PASS.

- [ ] **Step 8: Add the label input to the field row template**

In `issuer_schema_builder.html`, the `_field_row` template's grid is currently `grid-template-columns:1fr 160px 72px 36px`. Add a column for the label:

```html
<div style="display:grid;grid-template-columns:1fr 1fr 160px 72px 36px;gap:0.5rem;align-items:center">
  <input type="text"
         name="field_name_{{.Idx}}"
         value="{{.Field.Name}}"
         placeholder="field_name"
         pattern="[a-zA-Z_][a-zA-Z0-9_]*"
         title="Solo letras (a-z, A-Z), dígitos y guión bajo. No se permiten caracteres especiales (ñ, tildes, espacios)."
         style="background:var(--bg);border:1px solid var(--line);padding:0.55rem 0.7rem;font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:var(--ink);border-radius:2px">

  {{/* Label is free text — the identifier above must stay interoperable
       (it travels into the signed credential), but what the holder reads
       does not. Blank derives from the identifier, matching what wallets
       already do. */}}
  <input type="text"
         name="field_label_{{.Idx}}"
         value="{{index .Field.Labels "en"}}"
         placeholder="Label (English)"
         style="background:var(--bg);border:1px solid var(--line);padding:0.55rem 0.7rem;font-size:0.82rem;color:var(--ink);border-radius:2px">
```

Keep the existing datatype select, required checkbox, and remove button after these.

- [ ] **Step 9: Add the additional-locales control**

Below each field row, render existing non-English labels and give the operator a way to add one. Both the locale code and the value are free text:

```html
  {{range $loc, $val := .Field.Labels}}
    {{if ne $loc "en"}}
      <div style="grid-column:1/-1;display:grid;grid-template-columns:120px 1fr;gap:0.5rem;padding-left:1rem">
        <input type="text" value="{{$loc}}" readonly
               style="background:var(--bg-mute);border:1px solid var(--line);padding:0.4rem 0.6rem;font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--ink-mute);border-radius:2px">
        <input type="text" name="field_label_{{$.Idx}}_{{$loc}}" value="{{$val}}"
               style="background:var(--bg);border:1px solid var(--line);padding:0.4rem 0.6rem;font-size:0.78rem;color:var(--ink);border-radius:2px">
      </div>
    {{end}}
  {{end}}
  <div style="grid-column:1/-1;display:grid;grid-template-columns:120px 1fr;gap:0.5rem;padding-left:1rem">
    <input type="text" name="new_locale_{{.Idx}}" placeholder="es-DO"
           title="Any BCP-47 code — es-DO, ht, qu. Not restricted to a fixed list."
           style="background:var(--bg);border:1px solid var(--line);padding:0.4rem 0.6rem;font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--ink);border-radius:2px">
    <input type="text" name="new_label_{{.Idx}}" placeholder="Label in that language"
           style="background:var(--bg);border:1px solid var(--line);padding:0.4rem 0.6rem;font-size:0.78rem;color:var(--ink);border-radius:2px">
  </div>
```

- [ ] **Step 10: Parse the new-locale pair**

In the same parsing loop, after the prefix scan:

```go
		// A newly typed locale/label pair, from the empty row the template
		// always renders. Both must be non-empty to count.
		newLoc := strings.TrimSpace(form.Get(fmt.Sprintf("new_locale_%d", i)))
		newLabel := strings.TrimSpace(form.Get(fmt.Sprintf("new_label_%d", i)))
		if newLoc != "" && newLabel != "" {
			if spec.Labels == nil {
				spec.Labels = map[string]string{}
			}
			spec.Labels[newLoc] = newLabel
		}
```

- [ ] **Step 11: Test the new-locale path**

Append to `schema_labels_test.go`:

```go
func TestParseNewLocalePair(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_label_0", "Family Name")
	form.Set("new_locale_0", "qu")
	form.Set("new_label_0", "Sutiyki")

	fields := parseFieldSpecsFromForm(form)
	if got := fields[0].Labels["qu"]; got != "Sutiyki" {
		t.Errorf("new locale qu = %q, want Sutiyki", got)
	}
}

func TestParseNewLocaleIgnoresHalfFilledPair(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("new_locale_0", "qu") // locale typed, label left blank
	fields := parseFieldSpecsFromForm(form)
	if _, exists := fields[0].Labels["qu"]; exists {
		t.Error("half-filled locale pair should be ignored")
	}
}
```

- [ ] **Step 12: Run the handler suite**

```bash
cd verifiably/verifiably-go
gofmt -l internal/handlers/ templates/
go vet ./internal/handlers/
go test ./internal/handlers/ -v 2>&1 | tail -25
```

Expected: clean and PASS.

- [ ] **Step 13: Verify the template renders**

```bash
cd verifiably/verifiably-go
go test ./internal/handlers/ -run "Template|Render" -v 2>&1 | tail -20
```

If the repo has no template-render test, boot the server and load `/issuer/schema/build` manually, confirming the label column appears and a saved schema round-trips its labels.

- [ ] **Step 14: Commit**

```bash
cd verifiably
git add verifiably-go/internal/handlers/ verifiably-go/templates/
git commit -m "feat(ui): let operators label fields per language in the schema builder

The identifier input keeps its strict pattern because it travels into the
signed credential and must stay interoperable; the new label input beside it
is free text, because what the holder reads does not.

Locale codes are typed, not selected. OID4VCI leaves the vocabulary open, so
a dropdown would arbitrarily restrict which languages a deployment can serve.
Discovery is a prefix scan over the submitted form rather than a lookup
against a known list.

Leaving a label blank keeps FieldSpec.Labels empty, which derives from the
identifier — the same string wallets already show today."
```

---

### Task 6b: Preload mandatory docType fields in the builder

**Files:**
- Create: `verifiably-go/internal/mdoc/doctypes.go`
- Modify: `verifiably-go/templates/pages/issuer_schema_builder.html` (docType selector)
- Modify: `verifiably-go/internal/handlers/schema.go` (handle the selector)
- Test: `verifiably-go/internal/mdoc/doctypes_test.go`

**Interfaces:**
- Consumes: `vctypes.FieldSpec` with `Labels` (Task 4).
- Produces:
  - `func MandatoryFields(docType string) []vctypes.FieldSpec`
  - `func KnownDocTypes() []DocTypeInfo` where `DocTypeInfo` is `struct{ DocType, Name string }`

This is the "known docTypes" half of the spec's catalog section. Task 3's `docTypeProfiles` handles routing; this handles what the operator sees.

- [ ] **Step 1: Write the failing test**

Create `verifiably-go/internal/mdoc/doctypes_test.go`:

```go
package mdoc

import "testing"

func TestMandatoryFieldsMDL(t *testing.T) {
	fields := MandatoryFields("org.iso.18013.5.1.mDL")

	// ISO/IEC 18013-5 Table 3 defines exactly 11 mandatory elements.
	if len(fields) != 11 {
		t.Fatalf("mDL: got %d mandatory fields, want 11", len(fields))
	}

	byName := map[string]bool{}
	for _, f := range fields {
		byName[f.Name] = true
		if !f.Required {
			t.Errorf("%s: mandatory field not marked Required", f.Name)
		}
		if f.Labels["en"] == "" {
			t.Errorf("%s: missing English label", f.Name)
		}
	}
	for _, want := range []string{
		"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
		"issuing_country", "issuing_authority", "document_number", "portrait",
		"driving_privileges", "un_distinguishing_sign",
	} {
		if !byName[want] {
			t.Errorf("mDL missing mandatory element %q", want)
		}
	}
}

func TestMandatoryFieldsPhotoID(t *testing.T) {
	fields := MandatoryFields("org.iso.23220.photoID.1")

	// ISO/IEC 23220 defines 9 mandatory elements in org.iso.23220.1.
	if len(fields) != 9 {
		t.Fatalf("photoID: got %d mandatory fields, want 9", len(fields))
	}
	byName := map[string]bool{}
	for _, f := range fields {
		byName[f.Name] = true
	}
	// age_over_18 is mandatory here but optional in mDL — the clearest
	// evidence that the mandatory set belongs to the docType, not the format.
	if !byName["age_over_18"] {
		t.Error("photoID must include age_over_18 as mandatory")
	}
	if !byName["issuing_authority_unicode"] {
		t.Error("photoID uses issuing_authority_unicode, not issuing_authority")
	}
}

func TestMandatoryFieldsUnknownDocType(t *testing.T) {
	if got := MandatoryFields("org.iso.7367.1.mVRC"); got != nil {
		t.Errorf("unknown docType should return nil, got %v", got)
	}
}

func TestKnownDocTypes(t *testing.T) {
	known := KnownDocTypes()
	if len(known) != 2 {
		t.Fatalf("got %d known docTypes, want 2 (mDL, photoID)", len(known))
	}
	for _, d := range known {
		if d.DocType == "" || d.Name == "" {
			t.Errorf("incomplete entry: %+v", d)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd verifiably/verifiably-go
go test ./internal/mdoc/ -v
```

Expected: FAIL — the package does not exist.

- [ ] **Step 3: Implement the docType catalog**

Create `verifiably-go/internal/mdoc/doctypes.go`:

```go
// Package mdoc describes the ISO document types this system can issue in the
// mso_mdoc container format.
//
// mso_mdoc is the container (CBOR, COSE, MSO, X.509 chain) defined by
// ISO/IEC 18013-5. A docType names what document travels inside it. The
// mandatory element set belongs to the DOCTYPE, not the container: mDL
// defines 11 in one namespace, Photo ID defines 9 in org.iso.23220.1 — and
// age_over_18 is mandatory for Photo ID while merely optional for mDL.
//
// Only docTypes with a profile versioned in
// deploy/k8s/config/issuer2/issuer2-profiles.conf appear here. issuer-api2
// rejects a profileId it cannot resolve, so offering an unbacked docType in
// the UI would produce a failure at issuance time, in front of a citizen.
package mdoc

import "github.com/verifiably/verifiably-go/vctypes"

// DocTypeInfo identifies a docType for display in a selector.
type DocTypeInfo struct {
	DocType string
	Name    string
}

// KnownDocTypes lists the docTypes the operator may choose, in display order.
func KnownDocTypes() []DocTypeInfo {
	return []DocTypeInfo{
		{DocType: "org.iso.18013.5.1.mDL", Name: "Mobile Driving Licence (ISO 18013-5)"},
		{DocType: "org.iso.23220.photoID.1", Name: "Photo ID (ISO 23220)"},
	}
}

func req(name, label string) vctypes.FieldSpec {
	return vctypes.FieldSpec{
		Name:     name,
		Datatype: "string",
		Required: true,
		Labels:   map[string]string{"en": label},
	}
}

// mdlMandatory is ISO/IEC 18013-5 Table 3's mandatory set — the same 11
// elements internal/mdl/doctype.go emits, kept in step with it.
var mdlMandatory = []vctypes.FieldSpec{
	req("family_name", "Family Name"),
	req("given_name", "Given Name"),
	req("birth_date", "Date of Birth"),
	req("issue_date", "Date of Issue"),
	req("expiry_date", "Date of Expiry"),
	req("issuing_country", "Issuing Country"),
	req("issuing_authority", "Issuing Authority"),
	req("document_number", "Document Number"),
	req("portrait", "Portrait"),
	req("driving_privileges", "Driving Privileges"),
	req("un_distinguishing_sign", "UN Distinguishing Sign"),
}

// photoIDMandatory is ISO/IEC 23220's mandatory set in org.iso.23220.1.
// Note the differences from mDL that make this genuinely per-docType:
// age_over_18 is mandatory here, and the authority field is
// issuing_authority_unicode rather than issuing_authority.
var photoIDMandatory = []vctypes.FieldSpec{
	req("family_name", "Family Name"),
	req("given_name", "Given Name"),
	req("birth_date", "Date of Birth"),
	req("portrait", "Portrait"),
	req("issue_date", "Date of Issue"),
	req("expiry_date", "Date of Expiry"),
	req("issuing_authority_unicode", "Issuing Authority"),
	req("issuing_country", "Issuing Country"),
	{
		Name:     "age_over_18",
		Datatype: "boolean",
		Required: true,
		Labels:   map[string]string{"en": "Age Over 18"},
	},
}

var mandatoryByDocType = map[string][]vctypes.FieldSpec{
	"org.iso.18013.5.1.mDL":   mdlMandatory,
	"org.iso.23220.photoID.1": photoIDMandatory,
}

// MandatoryFields returns the elements the standard requires for a docType.
// Returns nil for an unknown docType. The caller must copy before mutating —
// the returned slice backs a package-level var.
func MandatoryFields(docType string) []vctypes.FieldSpec {
	src, ok := mandatoryByDocType[docType]
	if !ok {
		return nil
	}
	out := make([]vctypes.FieldSpec, len(src))
	copy(out, src)
	return out
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
cd verifiably/verifiably-go
go test ./internal/mdoc/ -v
```

Expected: all four PASS.

- [ ] **Step 5: Cross-check the mDL list against the existing issuer**

`internal/mdl/doctype.go` already enumerates the same elements. They must not drift.

```bash
cd verifiably/verifiably-go
grep -A 20 "var DatasetElements" internal/mdl/doctype.go
```

Confirm the 11 mandatory names match. `DatasetElements` additionally carries `age_over_18` and `age_over_21`, which are optional for mDL — correctly absent from the mandatory list here.

- [ ] **Step 6: Add a test that pins the two lists together**

Append to `doctypes_test.go`:

```go
// The mandatory list here and internal/mdl's emitted dataset describe the
// same standard. If one gains an element the other must too, so pin them.
func TestMDLMandatorySubsetOfIssuerDataset(t *testing.T) {
	issued := map[string]bool{}
	for _, e := range mdl.DatasetElements {
		issued[e] = true
	}
	for _, f := range MandatoryFields("org.iso.18013.5.1.mDL") {
		if !issued[f.Name] {
			t.Errorf("%q is mandatory but internal/mdl does not emit it", f.Name)
		}
	}
}
```

Add the import `"github.com/verifiably/verifiably-go/internal/mdl"`.

- [ ] **Step 7: Run it**

```bash
cd verifiably/verifiably-go
go test ./internal/mdoc/ -run TestMDLMandatorySubset -v
```

Expected: PASS. A failure means the two lists disagree — fix the disagreement, do not weaken the test.

- [ ] **Step 8: Add the docType selector to the builder template**

In `issuer_schema_builder.html`, after the Format select, add a block shown only when `mso_mdoc` is selected:

```html
  {{if eq .Std "mso_mdoc"}}
  <div class="field">
    <label>Document type
      <span style="font-size:0.7rem;color:var(--ink-mute);font-weight:400;margin-left:0.25rem">(which ISO document travels inside the mdoc container)</span>
    </label>
    <select name="doctype"
            hx-post="/issuer/schema/build/preview"
            hx-include="#builder-form-el"
            hx-target="#json-preview">
      {{$cur := .DocType}}
      {{range .KnownDocTypes}}
        <option value="{{.DocType}}" {{if eq $cur .DocType}}selected{{end}}>{{.Name}}</option>
      {{end}}
    </select>
    <p class="hint" style="font-size:0.75rem;color:var(--ink-mute);margin-top:0.35rem">
      The standard's mandatory fields are added automatically and cannot be removed.
      Add your own fields below — they go in your own namespace, not the ISO one.
    </p>
  </div>
  {{end}}
```

- [ ] **Step 9: Preload the mandatory fields when a docType is picked**

In the builder-data function in `schema.go`, after parsing `Std` and the new `doctype` value:

```go
	// For mdoc, the standard's mandatory elements are preloaded and locked:
	// the docType defines them, so an operator cannot omit or rename one and
	// still have a conformant credential. Their labels stay editable.
	if d.Std == "mso_mdoc" && d.DocType != "" {
		mandatory := mdoc.MandatoryFields(d.DocType)
		existing := map[string]bool{}
		for _, f := range d.Fields {
			existing[f.Name] = true
		}
		var merged []vctypes.FieldSpec
		for _, m := range mandatory {
			if submitted, ok := findFieldByName(d.Fields, m.Name); ok {
				// Keep the operator's labels; the identifier is fixed.
				m.Labels = submitted.Labels
			}
			merged = append(merged, m)
		}
		for _, f := range d.Fields {
			if !isMandatoryName(mandatory, f.Name) {
				merged = append(merged, f)
			}
		}
		d.Fields = merged
	}
```

Add the two helpers next to it:

```go
func findFieldByName(fields []vctypes.FieldSpec, name string) (vctypes.FieldSpec, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f, true
		}
	}
	return vctypes.FieldSpec{}, false
}

func isMandatoryName(mandatory []vctypes.FieldSpec, name string) bool {
	for _, m := range mandatory {
		if m.Name == name {
			return true
		}
	}
	return false
}
```

- [ ] **Step 10: Lock the identifier input for mandatory fields**

The `_field_row` template needs to know whether a row is mandatory. Pass a `Locked` flag alongside `Field`, and when set, render the identifier input as `readonly` with a tooltip explaining the standard defines it. Leave the label input editable.

- [ ] **Step 11: Run everything**

```bash
cd verifiably/verifiably-go
gofmt -l internal/mdoc/ internal/handlers/ templates/
go vet ./internal/mdoc/ ./internal/handlers/
go test ./internal/mdoc/ ./internal/handlers/ -v 2>&1 | tail -25
```

Expected: clean and PASS.

- [ ] **Step 12: Commit**

```bash
cd verifiably
git add verifiably-go/internal/mdoc/ verifiably-go/internal/handlers/ verifiably-go/templates/
git commit -m "feat(mdoc): preload each docType's mandatory fields in the builder

mso_mdoc is a container; the mandatory element set belongs to the docType
inside it. mDL requires 11 elements in one namespace, Photo ID requires 9 in
org.iso.23220.1 — and age_over_18 is mandatory for Photo ID while optional
for mDL. Modelling this per docType rather than per format is what keeps
adding a third one mechanical.

Only docTypes with a versioned issuer-api2 profile are offered. issuer-api2
rejects a profileId it cannot resolve, so listing an unbacked docType would
fail at issuance time in front of a citizen instead of at selection.

Mandatory identifiers are locked because the standard fixes them; their
labels stay editable, since what the holder reads is not what the credential
carries. Operator-added fields go in their own namespace — putting them in
org.iso.18013.5.1 would break conformance.

A test pins this list against internal/mdl's emitted dataset so the two
descriptions of the same standard cannot drift apart."
```

---

### Task 7: Publish the issuer display name

**Files:**
- Modify: `verifiably-go/deploy/k8s/config/issuer2/credential-issuer-metadata.conf` (create by extraction if absent)
- Modify: `verifiably-go/deploy/k8s/config/issuer/credential-issuer-metadata.conf`
- Modify: `verifiably-go/deploy/compose/hub/.env.example`

**Interfaces:**
- Consumes: Task 1's 0.23.1 (the field does not exist at 0.18.2) and Task 2's config directory.
- Produces: a root-level `display` array in both services' `/.well-known/openid-credential-issuer`.

- [ ] **Step 1: Confirm the field is supported and currently unset**

```bash
cd verifiably/verifiably-go
grep -n "issuerDisplay" deploy/k8s/config/issuer/credential-issuer-metadata.conf || \
  echo "not present — the shipped default has it commented out"
```

- [ ] **Step 2: Add the block to the legacy issuer's config**

At the top of `deploy/k8s/config/issuer/credential-issuer-metadata.conf`:

```hocon
# Root-level issuer branding, surfaced at /.well-known/openid-credential-issuer.
# Without it a wallet shows the raw issuer URL to the citizen downloading a
# credential. Per deployment, not per schema: walt.id accepts one
# issuerDisplay per service, so a deployment serving two authorities needs two
# instances — which is how walt.id models it.
#
# Locale entries follow the same convention as field labels: English is the
# base, any BCP-47 code may be added.
issuerDisplay = [
  {
    name = ${?VERIFIABLY_ISSUER_DISPLAY_NAME}
    locale = "en"
    description = ${?VERIFIABLY_ISSUER_DESCRIPTION}
  }
]
```

`${?VAR}` (with the question mark) omits the key when the variable is unset, rather than failing to start — correct here, since a deployment that has not configured branding should keep working exactly as today.

- [ ] **Step 3: Add the same block to issuer2's config**

Apply the identical block to `deploy/k8s/config/issuer2/credential-issuer-metadata.conf`. Extract the shipped file first if Task 2 did not already:

```bash
cd verifiably
docker create --name i2meta waltid/issuer-api2:0.23.1
docker cp i2meta:/waltid-issuer-api2/config/credential-issuer-metadata.conf \
  verifiably-go/deploy/k8s/config/issuer2/credential-issuer-metadata.conf
docker rm i2meta
```

- [ ] **Step 4: Pass the variables through in compose**

Add to the `environment:` block of both `issuer-api` and `issuer-api2` in `deploy/compose/stack/docker-compose.yml`:

```yaml
      VERIFIABLY_ISSUER_DISPLAY_NAME: ${VERIFIABLY_ISSUER_DISPLAY_NAME:-}
      VERIFIABLY_ISSUER_DESCRIPTION: ${VERIFIABLY_ISSUER_DESCRIPTION:-}
```

- [ ] **Step 5: Document them**

Append to `.env.example`:

```bash
# Issuer branding shown to the citizen when downloading a credential.
# Unset means the wallet falls back to displaying the raw issuer URL.
# Requires walt.id >= 0.21 (the field does not exist at 0.18.2).
VERIFIABLY_ISSUER_DISPLAY_NAME=
VERIFIABLY_ISSUER_DESCRIPTION=
```

- [ ] **Step 6: Verify it surfaces in the wellknown**

```bash
cd verifiably/verifiably-go/deploy/compose/stack
VERIFIABLY_ISSUER_DISPLAY_NAME="INTRANT" \
VERIFIABLY_ISSUER_DESCRIPTION="Instituto Nacional de Transito y Transporte Terrestre" \
  docker compose up -d issuer-api
sleep 20
curl -s http://localhost:7002/draft13/.well-known/openid-credential-issuer | \
  python -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('display','ABSENT'), indent=2))"
```

Expected: a `display` array with `name: "INTRANT"`. If `ABSENT`, the HOCON did not take — check the variable reached the container.

- [ ] **Step 7: Verify the unset case still boots**

```bash
cd verifiably/verifiably-go/deploy/compose/stack
docker compose down issuer-api && docker compose up -d issuer-api
sleep 20
docker compose logs issuer-api --tail 10
```

Expected: starts normally. `${?VAR}` must omit the key, not produce a malformed config — a deployment that never sets branding cannot be broken by this change.

- [ ] **Step 8: Commit**

```bash
cd verifiably
git add verifiably-go/deploy/
git commit -m "feat(deploy): publish issuer display name in the wellknown

Citizens downloading a credential saw the raw issuer URL. OID4VCI defines a
root-level issuer display for this; 0.18.2 lacked it, which is why
vctypes.go documents composing IssuerDisplayName into the credential
description as the only surface that propagated. The upgrade makes the real
field available.

Per deployment, not per schema: walt.id accepts one issuerDisplay per
service, so per-schema would force picking a winner. Two authorities means
two instances, which is how walt.id models it.

Uses \${?VAR} so an unconfigured deployment omits the key and keeps working
exactly as before, rather than failing to boot.

Schema.IssuerDisplayName is untouched — it still serves the verifier panel
and external wallets that do not read root-level display. This adds the
missing surface rather than replacing the existing one."
```

---

### Task 8: End-to-end verification

**Files:**
- Create: `verifiably-go/docs/mdl-issuance-manual-checklist.md`
- Test: uses `verifiably-go/internal/mdl/testdata/verify/verify.mjs` (from Task 0's branch)

**Interfaces:**
- Consumes: everything from Tasks 1-7.
- Produces: a written record that a real mDL and Photo ID were issued and independently verified.

- [ ] **Step 1: Bring the stack up**

```bash
cd verifiably/verifiably-go/deploy/compose/stack
docker compose up -d
sleep 40
docker compose ps
```

Expected: `issuer-api`, `issuer-api2`, and `verifiably-go` all `Up`.

- [ ] **Step 2: Issue an mDL through the real operator flow**

In the browser: pick walt.id → pick the mDL schema → fill the fields → issue. Use the UI, not curl — the point is to prove the path the operator actually takes.

Record the offer URI.

- [ ] **Step 3: Confirm the offer carries the issuer display name**

```bash
curl -s "http://localhost:7002/draft13/.well-known/openid-credential-issuer" | \
  python -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('display'), indent=2))"
```

Expected: the configured name, not the URL.

- [ ] **Step 4: Retrieve the credential and verify its CBOR types independently**

Complete the OID4VCI exchange to obtain the mdoc, then:

```bash
cd verifiably/verifiably-go/internal/mdl/testdata/verify
npm install
node verify.mjs <path-to-issued-mdoc>
```

Expected output confirms: `birth_date` as tag 1004 (`full-date`), `portrait` as a byte string, a valid signature and certificate chain.

This is the payoff of keeping `internal/mdl/` as a verifier: an implementation independent of walt.id checking walt.id's output.

- [ ] **Step 5: Verify the omission safety property with a real issuance**

Issue an mDL filling in **only** `family_name` and `given_name`, then decode it and confirm no Austrian sample data appears — no `Musterfrau`, no `AT`, no `Bundesministerium`.

The unit test in Task 3 pins the request side; this pins the whole path including the profile's emptied data.

- [ ] **Step 6: Repeat for Photo ID**

Same flow with the Photo ID schema. Its mandatory set differs (9 fields in `org.iso.23220.1`), which is what proves the design is genuinely per-docType rather than hardcoded to mDL.

- [ ] **Step 7: Verify with the real reader**

Present the issued mDL to `multipaz-identity-reader`, importing the IACA through its UI as in previous sessions. Confirm it verifies and the portrait renders.

- [ ] **Step 8: Write the checklist document**

Create `verifiably-go/docs/mdl-issuance-manual-checklist.md` recording each step above with its actual result, the walt.id version, the date, and any deviation. Note explicitly which steps are manual and must be repeated on the next upgrade.

- [ ] **Step 9: Commit**

```bash
cd verifiably
git add verifiably-go/docs/mdl-issuance-manual-checklist.md
git commit -m "docs(mdl): record the end-to-end issuance verification

Covers both docTypes through the real operator flow, CBOR types checked by
the independent Node verifier rather than by our own encoder, and the
omission safety property confirmed on a real issuance rather than only in a
unit test.

Written down because several of these steps are manual and must be repeated
on the next walt.id upgrade — the value is in the next person knowing
exactly what to redo."
```

---

### Task 9: Record the deferred documentation debt

**Files:**
- Modify: `verifiably-go/TODO.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a written record of what this PR deliberately did not do.

- [ ] **Step 1: Count the stale comments**

```bash
cd verifiably/verifiably-go
grep -rn "0\.18\.2" --include="*.go" . | grep -v node_modules | wc -l
```

- [ ] **Step 2: Add the entry to TODO.md**

Four items, all deferred deliberately during execution. Record all of them.

```markdown
## walt.id integration test cannot run under Docker-in-Docker

`TestIntegration_WaltidParsesAppendedCatalog` mounts a `t.TempDir()` path
into a `docker run` aimed at the host daemon. When the test itself runs
inside a container (necessary on a machine with no host Go toolchain), that
path does not exist on the host, so Docker silently mounts an **empty**
directory and walt.id dies with
`IllegalArgumentException: No loaded configuration: "issuer-service"`.

Proven during the 0.23.1 upgrade by mounting a deliberately empty directory
into the same image and reproducing the error verbatim. Nothing is wrong
with the image or the repo's config — the config simply never arrives.

The test also polls `http://localhost:hostPort` after publishing to the
host, which fails from inside a container for a second, independent reason.

Fix options: give the test a shared Docker network and address the container
by name, or copy the fixture to a host-visible path, or install Go on the
host. Until then the test is manual-only and cannot gate an upgrade.

**Consequence for the 0.23.1 upgrade (commits `0293227`..`f1050a3`):** the
task's designated Step 3 verification never ran green. The upgrade rests
instead on the full unit suite passing and on the design-phase spike, which
issued real credentials against a live 0.23.1 across all four code paths
(`jwt_vc_json` with and without `credentialStatus`, `vc+sd-jwt`,
`mso_mdoc`). Recorded here because `git log` alone does not show it.

## DirectPDFPlain capability claim unverified for 0.23.1

`scripts/gen-backends.sh:82` now reads "No documented QR-on-PDF export at
v0.23.1." The version was updated with the other pins, but nobody confirmed
0.23.x did not add QR-on-PDF export. It is a negative claim, so it stays
true unless the feature landed between 0.19 and 0.23 — worth a check against
the release notes when someone is in there anyway.

## docs/ still cites walt.id 0.18.2

`docs/dpg/walt-id.md` and `docs/dpg-matrix.md` describe the same
operator-facing DPG capabilities that `gen-backends.sh` renders, and still
say 0.18.2. Outside the upgrade's file glob (`.md` was not in scope), so
deliberately untouched — but now inconsistent with the `.sh` strings.

## walt.id 0.18.2 references in Go comments

The 2026-08-21 upgrade to 0.23.1 changed every executable pin but left the
documentation comments that cite v0.18.2 as the version whose source was
read to verify a behaviour (`config.go`, `issuer.go`, `verifier.go`,
`wallet.go`, `catalog.go`, `vctypes.go`, several handlers).

Not bugs — the documented behaviour was re-verified at 0.23.1 by the
integration test and the design spike. But they now claim to describe a
version the system no longer runs, which will mislead the next reader.

Deliberately deferred so the upgrade diff stayed reviewable. Worth a
mechanical follow-up pass.
```

- [ ] **Step 3: Commit**

```bash
cd verifiably
git add verifiably-go/TODO.md
git commit -m "docs: record stale 0.18.2 comment references as follow-up debt

Deferred from the upgrade so its diff stayed reviewable. Recorded rather
than left silent, because a comment claiming to describe a version we no
longer run misleads the next reader."
```

---

## Execution notes

**Task order is not negotiable for 0 → 1 → 2 → 3.** Task 0 makes the referenced files exist; Task 1 makes `issuer-api2` available at all; Task 2 makes it reachable; Task 3 uses it.

**Tasks 4 → 5 → 6 → 6b are their own chain** (model → catalog → UI → docType preload). They can run in parallel with 1-3 by a second worker up to Task 6b, which touches `internal/handlers/schema.go` and the builder template alongside Task 6 — run 6b after 6, not concurrently.

Task 6b also reads `internal/mdl/doctype.go` for its cross-check test, so it inherits Task 0's branch dependency.

**Task 7 needs Task 1** (the field does not exist at 0.18.2) and Task 2's config directory.

**Task 8 needs everything.** Task 9 is independent and can land any time.

**On the single PR:** the spec asked for one PR carrying all of this. Keep the commits as written — each is independently reviewable, and a reviewer can evaluate the upgrade without untangling it from the label work.