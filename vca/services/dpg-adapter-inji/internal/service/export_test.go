// SPDX-License-Identifier: Apache-2.0

package service

// LegacyHolderKeys returns the store keys of a holder record that an
// earlier release wrote: under the subject and under the Mimoto wallet
// id, which it gave wallet-auth.
func LegacyHolderKeys(subject, walletID string) []string {
	return []string{subjectKey(subject), walletKey(walletID)}
}
