// SPDX-License-Identifier: Apache-2.0

// Package docs embeds the reader documents of this folder. The help
// page of each portal renders the documents of its role from them, so
// the help reads the same text as the repository.
package docs

import "embed"

// FS holds every Markdown document of the folder.
//
//go:embed *.md
var FS embed.FS
