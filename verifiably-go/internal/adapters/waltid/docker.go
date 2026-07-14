package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dockerSocketPath is the host-side Unix socket the verifiably-go container
// must mount in to control sibling Compose services. /var/run/docker.sock is
// the canonical Docker Engine API endpoint; deploy.sh bind-mounts it into the
// verifiably-go container alongside the issuer-api/config volume.
const dockerSocketPath = "/var/run/docker.sock"

// dockerClient talks to the Docker Engine API over the Unix socket. The
// HTTP host portion ("localhost") is meaningless on a Unix-socket dial — net.Dial
// ignores the addr arg and uses the socket path. 60-second timeout is a generous
// upper bound for restart calls (issuer-api typically restarts in under 10s).
var dockerClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", dockerSocketPath)
		},
	},
	Timeout: 60 * time.Second,
}

// findContainerByService resolves a Docker Compose service name (e.g. "issuer-api")
// to a container ID by querying the Engine API with the canonical
// `com.docker.compose.service=<name>` label filter Compose stamps on every
// container it creates. Returns an error if no container matches — caller can
// surface a clear "stack not running" message rather than guessing.
func findContainerByService(serviceName string) (string, error) {
	filters := fmt.Sprintf(`{"label":["com.docker.compose.service=%s"]}`, serviceName)
	u := "http://docker/containers/json?filters=" + url.QueryEscape(filters)
	resp, err := dockerClient.Get(u)
	if err != nil {
		return "", fmt.Errorf("list containers: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read containers response: %w", err)
	}
	var containers []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
	}
	if err := json.Unmarshal(body, &containers); err != nil {
		return "", fmt.Errorf("parse containers: %w (body=%s)", err, truncateBody(string(body), 200))
	}
	if len(containers) == 0 {
		return "", fmt.Errorf("no container found for compose service %q", serviceName)
	}
	return containers[0].ID, nil
}

// restartContainer issues an Engine API restart against the container backing
// the given Compose service and polls for it to be running again. The 5s wait
// param mirrors `docker restart -t 5` — Compose-supervised services typically
// shut down on the first SIGTERM well within that.
//
// Returns nil even when the post-restart running poll times out: a slow boot
// is not the same as a failed restart, and the issue-flow that triggered this
// will fail loudly with a real error if the new walt.id process can't serve
// the next OID4VCI call.
func restartContainer(serviceName string) error {
	id, err := findContainerByService(serviceName)
	if err != nil {
		return fmt.Errorf("find container: %w", err)
	}
	u := fmt.Sprintf("http://docker/containers/%s/restart?t=5", id)
	req, err := http.NewRequest(http.MethodPost, u, nil)
	if err != nil {
		return fmt.Errorf("build restart request: %w", err)
	}
	resp, err := dockerClient.Do(req)
	if err != nil {
		return fmt.Errorf("restart container: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker restart returned %d: %s", resp.StatusCode, truncateBody(string(body), 200))
	}
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		if isContainerRunning(id) {
			return nil
		}
	}
	return nil
}

// waitForHTTPReady polls baseURL's OID4VCI metadata endpoint until the app
// responds (any HTTP status) or the timeout elapses, returning whether it became
// ready. A container's State.Running flips true as soon as the process starts —
// well before walt.id's issuer-api can serve — so restartContainer alone leaves
// the first post-restart OID4VCI/verify call to flap ("fails first, retry
// works", B4). Callers wait on this after restartContainer. Best-effort: returns
// false on timeout and the caller proceeds regardless.
func waitForHTTPReady(baseURL string, timeout time.Duration) bool {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return false
	}
	probe := baseURL + "/.well-known/openid-credential-issuer"
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	for {
		resp, err := client.Get(probe)
		if err == nil {
			resp.Body.Close()
			return true
		}
		if time.Now().After(deadline) {
			slog.Warn("waltid: issuer-api not ready before timeout", "url", baseURL, "err", err)
			return false
		}
		time.Sleep(1 * time.Second)
	}
}

// isContainerRunning probes a container's State.Running flag. False on any
// error — used only as a poll gate, so a transient failure just means we
// keep waiting.
func isContainerRunning(id string) bool {
	u := fmt.Sprintf("http://docker/containers/%s/json", id)
	resp, err := dockerClient.Get(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var info struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return false
	}
	return info.State.Running
}

func truncateBody(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}
