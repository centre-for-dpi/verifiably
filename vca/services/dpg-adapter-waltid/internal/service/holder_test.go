// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/service"
)

// registerWallet opens the wallet of one citizen.
func registerWallet(t *testing.T, svc *service.Service) string {
	t.Helper()
	resp, err := svc.Register(context.Background(), connect.NewRequest(&backendv1.RegisterRequest{
		PairwiseSubject: "https://idp.example.org|citizen-1",
	}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return resp.Msg.GetWalletId()
}

func TestAccountForIsTheSameForTheSameSubject(t *testing.T) {
	first := service.AccountFor("https://idp.example.org|citizen-1")
	again := service.AccountFor("https://idp.example.org|citizen-1")
	other := service.AccountFor("https://idp.example.org|citizen-2")
	if first != again {
		t.Fatal("the same subject must give the same account")
	}
	if first.Email == other.Email || first.Password == other.Password {
		t.Fatal("two subjects must not share an account")
	}
	if !strings.HasSuffix(first.Email, "@wallet.invalid") {
		t.Fatalf("email = %q, the domain must be reserved", first.Email)
	}
	if strings.Contains(first.Email, "citizen-1") {
		t.Fatal("the account must not carry the subject in the clear")
	}
}

func TestRegisterOpensTheWallet(t *testing.T) {
	svc, _ := newService(t, all)
	if got := registerWallet(t, svc); got != "7d0f9c1e-5b2a-4c8d-9e3f-1a2b3c4d5e6f" {
		t.Fatalf("wallet id = %q", got)
	}
}

func TestRegisterChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	_, err := svc.Register(context.Background(), connect.NewRequest(&backendv1.RegisterRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestRegisterReportsAFailedLogin(t *testing.T) {
	svc, f := newService(t, all)
	f.SetStatus("/wallet-api/auth/login", http.StatusUnauthorized)
	_, err := svc.Register(context.Background(), connect.NewRequest(&backendv1.RegisterRequest{
		PairwiseSubject: "https://idp.example.org|citizen-1",
	}))
	wantCode(t, err, connect.CodePermissionDenied)
}

func TestListCredentialsReturnsThePageAndTheClaimNames(t *testing.T) {
	svc, _ := newService(t, all)
	walletID := registerWallet(t, svc)
	resp, err := svc.ListCredentials(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: walletID}))
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(resp.Msg.GetCredentials()) != 1 {
		t.Fatalf("credentials = %d", len(resp.Msg.GetCredentials()))
	}
	got := resp.Msg.GetCredentials()[0]
	if got.GetType() != "UniversityDegree" {
		t.Fatalf("type = %q", got.GetType())
	}
	if !strings.HasPrefix(got.GetIssuer(), "did:key:") {
		t.Fatalf("issuer = %q", got.GetIssuer())
	}
	if got.GetCredential().GetFormat() != commonv1.Format_FORMAT_JWT_VC_JSON {
		t.Fatalf("format = %v", got.GetCredential().GetFormat())
	}
	if got.GetReceivedAt() == nil {
		t.Fatal("the receive time is missing")
	}
}

func TestListCredentialsNeedsAnOpenSession(t *testing.T) {
	svc, _ := newService(t, all)
	_, err := svc.ListCredentials(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: "unknown"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.ListCredentials(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialsRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestListCredentialsReportsAFailure(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	f.SetStatus("/wallet-api/wallet/"+walletID+"/credentials", http.StatusBadGateway)
	_, err := svc.ListCredentials(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: walletID}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestAcceptOfferReturnsTheNewCredential(t *testing.T) {
	svc, _ := newService(t, all)
	walletID := registerWallet(t, svc)
	resp, err := svc.AcceptOffer(context.Background(), connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: walletID,
		OfferUri: "openid-credential-offer://issuer.example.org?credential_offer_uri=https%3A%2F%2Fx",
	}))
	if err != nil {
		t.Fatalf("AcceptOffer: %v", err)
	}
	got := resp.Msg.GetCredential()
	if got.GetId() != "urn:uuid:8f4d1c62-77aa-4b19-8c05-3d9e7f1a2b34" {
		t.Fatalf("credential id = %q, want the one the wallet gained", got.GetId())
	}
	if got.GetCredential().GetFormat() != commonv1.Format_FORMAT_VC_SD_JWT {
		t.Fatalf("format = %v", got.GetCredential().GetFormat())
	}
	if got.GetType() != "https://walt-issuer.example.org/identity_credential" {
		t.Fatalf("type = %q, an SD-JWT VC uses its vct", got.GetType())
	}
}

func TestAcceptOfferChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	walletID := registerWallet(t, svc)
	_, err := svc.AcceptOffer(context.Background(),
		connect.NewRequest(&backendv1.AcceptOfferRequest{WalletId: walletID}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestAcceptOfferReportsAnOfferTheWalletCannotRead(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	path := "/wallet-api/wallet/" + walletID + "/exchange/resolveCredentialOffer"
	f.SetStatus(path, http.StatusBadRequest)
	_, err := svc.AcceptOffer(context.Background(), connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: walletID, OfferUri: "openid-credential-offer://broken",
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestAcceptOfferReportsAClaimThatAddsNothing(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	// The fake keeps the same credential list, so the wallet gained none.
	f.SetStatus("/wallet-api/wallet/"+walletID+"/exchange/useOfferRequest", http.StatusOK)
	_, err := svc.AcceptOffer(context.Background(), connect.NewRequest(&backendv1.AcceptOfferRequest{
		WalletId: walletID, OfferUri: "openid-credential-offer://x",
	}))
	wantCode(t, err, connect.CodeInternal)
}

func TestPresentSharesTheNamedClaims(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	resp, err := svc.Present(context.Background(), connect.NewRequest(&backendv1.PresentRequest{
		WalletId:        walletID,
		RequestUri:      "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier",
		CredentialIds:   []string{"urn:uuid:2b0c8a51-9c1d-4a77-9f3e-5c2f1d7b6a90"},
		DisclosedClaims: []string{"age_over_18"},
	}))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !resp.Msg.GetAccepted() {
		t.Fatal("the presentation was not accepted")
	}
	if resp.Msg.GetRedirectUri() == "" {
		t.Fatal("the redirect URI is missing")
	}
	body := string(f.Request("/wallet-api/wallet/" + walletID + "/exchange/usePresentationRequest"))
	if !strings.Contains(body, `"disclosures"`) || !strings.Contains(body, "age_over_18") {
		t.Fatalf("the wallet body %q does not limit the disclosures", body)
	}
}

func TestPresentChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	walletID := registerWallet(t, svc)
	_, err := svc.Present(context.Background(),
		connect.NewRequest(&backendv1.PresentRequest{WalletId: walletID}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestPresentReportsAFailure(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	f.SetStatus("/wallet-api/wallet/"+walletID+"/exchange/usePresentationRequest", http.StatusBadRequest)
	_, err := svc.Present(context.Background(), connect.NewRequest(&backendv1.PresentRequest{
		WalletId: walletID, RequestUri: "openid4vp://x", CredentialIds: []string{"a"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestDeleteCredentialRemovesOneCredential(t *testing.T) {
	svc, _ := newService(t, all)
	walletID := registerWallet(t, svc)
	_, err := svc.DeleteCredential(context.Background(), connect.NewRequest(&backendv1.DeleteCredentialRequest{
		WalletId: walletID, CredentialId: "urn:uuid:2b0c8a51-9c1d-4a77-9f3e-5c2f1d7b6a90",
	}))
	if err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
}

func TestDeleteCredentialChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	walletID := registerWallet(t, svc)
	_, err := svc.DeleteCredential(context.Background(),
		connect.NewRequest(&backendv1.DeleteCredentialRequest{WalletId: walletID}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestDeleteCredentialReportsAFailure(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	path := "/wallet-api/wallet/" + walletID + "/credentials/urn:uuid:gone"
	f.SetStatus(path, http.StatusNotFound)
	_, err := svc.DeleteCredential(context.Background(), connect.NewRequest(&backendv1.DeleteCredentialRequest{
		WalletId: walletID, CredentialId: "urn:uuid:gone",
	}))
	wantCode(t, err, connect.CodeNotFound)
}
