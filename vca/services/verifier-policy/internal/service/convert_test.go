// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
)

func TestFormatOf(t *testing.T) {
	cases := map[commonv1.Format]vc.Format{
		commonv1.Format_FORMAT_VC_SD_JWT:   vc.FormatSDJWT,
		commonv1.Format_FORMAT_DC_SD_JWT:   vc.FormatSDJWT,
		commonv1.Format_FORMAT_JWT_VC_JSON: vc.FormatJWT,
		commonv1.Format_FORMAT_LDP_VC:      vc.FormatJSONLD,
		commonv1.Format_FORMAT_LDP_VC_BBS:  vc.FormatJSONLD,
		commonv1.Format_FORMAT_MSO_MDOC:    vc.FormatMdoc,
		commonv1.Format_FORMAT_UNSPECIFIED: vc.FormatUnknown,
	}
	for in, want := range cases {
		if got := FormatOf(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestCarrierName(t *testing.T) {
	cases := map[ingestv1.Carrier]string{
		ingestv1.Carrier_CARRIER_OID4VP:      "oid4vp",
		ingestv1.Carrier_CARRIER_IMAGE:       "image",
		ingestv1.Carrier_CARRIER_PDF:         "pdf",
		ingestv1.Carrier_CARRIER_XML:         "xml",
		ingestv1.Carrier_CARRIER_JSON:        "json",
		ingestv1.Carrier_CARRIER_QR:          "qr",
		ingestv1.Carrier_CARRIER_QR_CLAIM169: "qr-claim169",
		ingestv1.Carrier_CARRIER_UNSPECIFIED: "unknown",
	}
	for in, want := range cases {
		if got := carrierName(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestToPresentationFromPayload(t *testing.T) {
	raw := &ingestv1.RawPresentation{
		Carrier: ingestv1.Carrier_CARRIER_JSON,
		Payload: []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"issuer":"did:web:a"}`),
	}
	got := ToPresentation(raw)
	if len(got.Credentials) != 1 {
		t.Fatalf("want one credential, got %d", len(got.Credentials))
	}
	c := got.Credentials[0]
	if c.Format != vc.FormatJSONLD || c.Token != "" || c.VC.Issuer != "did:web:a" {
		t.Fatalf("unexpected credential: %+v", c)
	}
	if ToPresentation(nil).Carrier != "unknown" {
		t.Fatal("want an unknown carrier for an empty message")
	}
}

func TestToPresentationBadPayload(t *testing.T) {
	raw := &ingestv1.RawPresentation{
		Credentials: []*commonv1.Credential{{Format: commonv1.Format_FORMAT_JWT_VC_JSON, Payload: []byte("nope")}},
	}
	got := ToPresentation(raw)
	if len(got.Credentials) != 1 || got.Credentials[0].VC.Issuer != "" {
		t.Fatalf("want an empty view, got %+v", got.Credentials)
	}
}

func TestOutcomeAndVerdict(t *testing.T) {
	outcomes := map[policy.Outcome]policyv1.Outcome{
		policy.Pass:             policyv1.Outcome_OUTCOME_PASS,
		policy.Fail:             policyv1.Outcome_OUTCOME_FAIL,
		policy.Skip:             policyv1.Outcome_OUTCOME_SKIP,
		policy.Error:            policyv1.Outcome_OUTCOME_ERROR,
		policy.Outcome("other"): policyv1.Outcome_OUTCOME_UNSPECIFIED,
	}
	for in, want := range outcomes {
		if got := outcomeOf(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
	verdicts := map[policy.Verdict]policyv1.EvaluateResponse_Verdict{
		policy.Valid:            policyv1.EvaluateResponse_VERDICT_VALID,
		policy.Invalid:          policyv1.EvaluateResponse_VERDICT_INVALID,
		policy.Indeterminate:    policyv1.EvaluateResponse_VERDICT_INDETERMINATE,
		policy.Verdict("other"): policyv1.EvaluateResponse_VERDICT_UNSPECIFIED,
	}
	for in, want := range verdicts {
		if got := VerdictOf(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestToProtoResults(t *testing.T) {
	got := ToProtoResults([]policy.CheckResult{{
		Name: policy.NameStatus, Result: policy.Pass, Detail: "ok",
		Evidence: map[string]string{"list": "x"}, CredentialIndex: 2,
	}})
	if len(got) != 1 || got[0].GetCredentialIndex() != 2 || got[0].GetEvidence()["list"] != "x" {
		t.Fatalf("unexpected results: %+v", got)
	}
}

func TestToCoreSet(t *testing.T) {
	got := ToCoreSet(&policyv1.PolicySet{
		Id: "one", Version: 3,
		Checks: []*policyv1.PolicySet_Check{{
			Name: policy.NameStatus, Blocking: true,
			Params: map[string]string{policy.ParamFailMode: policy.FailOpen},
		}},
	})
	if got.ID != "one" || got.Version != 3 || len(got.Settings) != 1 {
		t.Fatalf("unexpected set: %+v", got)
	}
	if !got.Settings[0].Blocking || got.Settings[0].Params[policy.ParamFailMode] != policy.FailOpen {
		t.Fatalf("unexpected setting: %+v", got.Settings[0])
	}
}
