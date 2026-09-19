// SPDX-License-Identifier: Apache-2.0

// Command demo serves the vca UI kit demo page on the PORT address (default 8080).
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/centre-for-dpi/vc-adapters/ui/example"
)

func main() {
	h, err := example.Handler()
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("demo on http://localhost:%s/", port)
	srv := &http.Server{Addr: ":" + port, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
