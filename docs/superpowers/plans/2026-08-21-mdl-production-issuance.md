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
	docType := schema.ID
	profileID, ok := profileIDForDocType(docType)
	if !ok {
		return issuer2OfferRequest{}, fmt.Errorf(
			"waltid: no issuer-api2 profile for docType %q — only pre-provisioned docTypes can be issued (see deploy/k8s/config/issuer2/issuer2-profiles.conf)",
			docType)
	}

	namespace := mdocNamespaceForDocType(docType)
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

- [ ] **Step 8: Check whether the namespace helper already exists before writing it**

`buildMdocData` already derives the namespace by stripping the doctype's last dot-segment (`issuer.go` around line 1317 documents this).

```bash
cd verifiably/verifiably-go
grep -n "func mdocNamespaceForDocType\|strip the doctype" internal/adapters/waltid/issuer.go
```

If a helper exists, use it and delete the reference to `mdocNamespaceForDocType` from Step 7. If only inline logic exists, extract it into `mdocNamespaceForDocType(docType string) string` in `issuer2.go` and have `buildMdocData` call it too — one definition, not two.

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