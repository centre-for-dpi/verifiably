// SPDX-License-Identifier: Apache-2.0

package app_test

import "os"

// osWriteFile creates an empty file at the path.
func osWriteFile(path string) error {
	return os.WriteFile(path, nil, 0o600)
}
