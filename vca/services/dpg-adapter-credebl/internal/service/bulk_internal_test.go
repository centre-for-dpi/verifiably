// SPDX-License-Identifier: Apache-2.0

package service

import (
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// TestRefusedCarriesTheSentenceOfThePlatform: the platform answers a bad
// file with a sentence, or a list of them for bad rows. The error keeps
// the sentence for the operator.
func TestRefusedCarriesTheSentenceOfThePlatform(t *testing.T) {
	cases := map[string]string{
		`{"statusCode":400,"message":"Invalid emails found in the chosen file"}`:                                    "Invalid emails found in the chosen file",
		`{"statusCode":400,"message":["Attribute name is required at row 1","Attribute age is required at row 2"]}`: "Attribute name is required at row 1; Attribute age is required at row 2",
		`{"statusCode":400,"message":{"nested":true}}`:                                                              "",
		`not json`: "",
	}
	for body, want := range cases {
		if got := platformReason(body); got != want {
			t.Errorf("platformReason(%s) = %q, want %q", body, got, want)
		}
	}
	err := refused("upload the bulk file", &dpgclient.StatusError{Status: http.StatusConflict,
		Body: `{"statusCode":409,"message":"Schema attributes are mismatched in the file header."}`})
	if err.Code() != connect.CodeAlreadyExists || !strings.Contains(err.Message(), "the platform refused: Schema attributes are mismatched") {
		t.Errorf("err = %v", err)
	}
	// A failure without a sentence keeps the plain error.
	err = refused("upload the bulk file", &dpgclient.StatusError{Status: http.StatusBadGateway, Body: "down"})
	if err.Code() != connect.CodeUnavailable {
		t.Errorf("err = %v", err)
	}
}
