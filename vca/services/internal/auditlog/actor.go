// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/internal/msg"
)

// ActorHeader carries the actor of a call between two VCA services. A
// service that checks no session itself, such as the trust registry,
// records the actor its caller names in it. The admin service sets it
// on each change it makes in the trust registry for an admin.
const ActorHeader = "X-Vca-Actor"

// maxActor caps the length of an actor.
const maxActor = 256

// ActorFrom returns the actor a caller names in the headers. An actor
// with a control character or of more than 256 bytes gives "".
func ActorFrom(h http.Header) string {
	v := strings.TrimSpace(h.Get(ActorHeader))
	if len(v) > maxActor {
		return ""
	}
	for _, r := range v {
		if r < ' ' || r == 0x7f {
			return ""
		}
	}
	return v
}

// actorKey is the context key of the actor.
type actorKey struct{}

// WithActor returns a context that carries actor. Record names it when
// the headers of a call name no actor.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorOf returns the actor of a context, or "".
func ActorOf(ctx context.Context) string {
	v, ok := ctx.Value(actorKey{}).(string)
	if !ok {
		return ""
	}
	return v
}

// Record writes the event of one call of a service that checks no
// session itself: the actor its caller names in h, or else the actor of
// ctx, the action, the target, and the outcome of err. A success keeps detail. A failure
// names the Connect code of err, never its text, which can hold a claim
// value (ADR-039 decision 3). A nil log writes nothing.
func (l *Log) Record(ctx context.Context, h http.Header, action, target, detail string, err error) {
	e := Entry{Action: action, Target: target, OK: err == nil, Detail: detail, Actor: ActorOf(ctx)}
	if named := ActorFrom(h); named != "" {
		e.Actor = named
	}
	if err != nil {
		e.Detail = msg.T("audit.reason.code", connect.CodeOf(err).String())
	}
	l.Write(ctx, e)
}
