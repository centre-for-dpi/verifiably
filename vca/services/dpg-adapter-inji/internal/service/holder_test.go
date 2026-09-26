// SPDX-License-Identifier: Apache-2.0

package service_test

import "testing"

// The holder role through Mimoto (P6-I7a decision, docs/dpg-adapter-inji.md).
// P6-I7b fills these tests.

// TestRegisterCreatesMimotoWallet logs in to Mimoto with the ID token of
// the holder login and makes one wallet with a PIN the adapter keeps.
func TestRegisterCreatesMimotoWallet(t *testing.T) { t.Skip("P6-I7b") }

// TestListCredentials lists the held credentials of the Mimoto wallet.
func TestListCredentials(t *testing.T) { t.Skip("P6-I7b") }

// TestAcceptOfferPointsAtInjiWeb answers unimplemented and names Inji
// Web, where the browser runs the download.
func TestAcceptOfferPointsAtInjiWeb(t *testing.T) { t.Skip("P6-I7b") }

// TestPresentThroughMimoto answers an OID4VP request through Mimoto.
func TestPresentThroughMimoto(t *testing.T) { t.Skip("P6-I7b") }

// TestDelete removes a credential from the Mimoto wallet.
func TestDelete(t *testing.T) { t.Skip("P6-I7b") }

// TestCapabilitiesListHolderRole lists the holder role and the Mimoto
// and Inji Web components with a Mimoto URL.
func TestCapabilitiesListHolderRole(t *testing.T) { t.Skip("P6-I7b") }
