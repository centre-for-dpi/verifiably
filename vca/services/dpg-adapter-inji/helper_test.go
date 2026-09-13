// SPDX-License-Identifier: Apache-2.0

package main

import "os"

// writeEmptyFile creates an empty file at the path.
func writeEmptyFile(path string) error {
	return os.WriteFile(path, nil, 0o600)
}
