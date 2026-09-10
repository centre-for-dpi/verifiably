package pg

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/verifiably/verifiably-go/internal/issuance"
)

// These tests need a real PostgreSQL: the issuance log is hand-rolled pgx with
// dynamically-built WHERE clauses and a hash chain, and a fake would only test
// the fake. CI provides one as a service container (see quality.yml); locally
// they skip unless VERIFIABLY_TEST_PG_DSN is set, e.g.
//
//	docker run --rm -d -p 5433:5432 -e POSTGRES_PASSWORD=pg postgres:16
//	VERIFIABLY_TEST_PG_DSN=postgres://postgres:pg@localhost:5433/postgres?sslmode=disable go test ./internal/storage/pg/
//
// Skipping rather than failing keeps `go test ./...` green on a laptop without
// Docker, which is how most of this repo's contributors run it.

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("VERIFIABLY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("VERIFIABLY_TEST_PG_DSN not set; skipping PostgreSQL integration tests")
	}
	pool, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	// Each test starts from an empty log so the hash chain and ordering
	// assertions are not affected by a previous test's rows.
	if _, err := pool.Exec(context.Background(), `TRUNCATE issued_credentials`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func sample(id, schema string) issuance.IssuedCredential {
	return issuance.IssuedCredential{
		ID:         id,
		SchemaID:   schema,
		SchemaName: schema,
		Std:        "sd_jwt_vc (IETF)",
		Format:     "vc+sd-jwt",
		IssuerDpg:  "Walt Community Stack",
		OwnerKey:   "operator-a",
		HolderHint: "holder@example.gov",
	}
}

// Append on an empty table reads the previous row to extend the hash chain and
// finds none. That pgx.ErrNoRows must be treated as "this is the first entry",
// not as a failure — errors.Is rather than ==, because pgx wraps.
func TestAppend_FirstEntryOnEmptyLog(t *testing.T) {
	pool := testPool(t)
	l := NewIssuanceLog(pool)

	got, err := l.Append(sample("vc-1", "Cedula"))
	if err != nil {
		t.Fatalf("first Append must succeed on an empty log: %v", err)
	}
	if got.ID != "vc-1" {
		t.Errorf("ID = %q, want vc-1", got.ID)
	}
}

func TestAppend_ChainsSubsequentEntries(t *testing.T) {
	pool := testPool(t)
	l := NewIssuanceLog(pool)

	if _, err := l.Append(sample("vc-1", "Cedula")); err != nil {
		t.Fatal(err)
	}
	second, err := l.Append(sample("vc-2", "Cedula"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if second.PrevHash == "" {
		t.Error("the second entry must carry the first entry's hash")
	}
}

// List builds its WHERE clause and its $n placeholders dynamically. A filter
// combination that exercises several branches at once is what catches an
// off-by-one in the placeholder counter — a class of bug that yields either a
// pgx argument-count error or, worse, a filter silently applied to the wrong
// column.
func TestList_FiltersCombine(t *testing.T) {
	pool := testPool(t)
	l := NewIssuanceLog(pool)

	for _, c := range []issuance.IssuedCredential{
		sample("vc-1", "Cedula"),
		sample("vc-2", "Licencia"),
	} {
		if _, err := l.Append(c); err != nil {
			t.Fatal(err)
		}
	}
	other := sample("vc-3", "Cedula")
	other.OwnerKey = "operator-b"
	if _, err := l.Append(other); err != nil {
		t.Fatal(err)
	}

	t.Run("owner scope", func(t *testing.T) {
		got := l.List(issuance.Filter{OwnerKey: "operator-a"})
		if len(got) != 2 {
			t.Errorf("got %d rows, want 2 for operator-a", len(got))
		}
	})

	t.Run("query narrows within owner", func(t *testing.T) {
		got := l.List(issuance.Filter{OwnerKey: "operator-a", Query: "Licencia"})
		if len(got) != 1 || got[0].ID != "vc-2" {
			t.Errorf("got %+v, want only vc-2", got)
		}
	})

	// Every filter at once: this is the placeholder-counter stress case.
	t.Run("all filters at once", func(t *testing.T) {
		got := l.List(issuance.Filter{
			OwnerKey: "operator-a",
			Std:      "sd_jwt_vc (IETF)",
			Format:   "vc+sd-jwt",
			State:    "active",
			Query:    "Cedula",
		})
		if len(got) != 1 || got[0].ID != "vc-1" {
			t.Errorf("got %+v, want only vc-1", got)
		}
	})
}

// Revocation is owner-scoped: operator B must not be able to revoke operator
// A's credential by guessing its id. The scoped UPDATE returns no rows, and
// that pgx.ErrNoRows has to become a clear "not found or not owned" error
// rather than being reported as a database failure.
func TestMarkRevoked_OwnerScoped(t *testing.T) {
	pool := testPool(t)
	l := NewIssuanceLog(pool)

	if _, err := l.Append(sample("vc-1", "Cedula")); err != nil {
		t.Fatal(err)
	}

	t.Run("wrong owner is refused", func(t *testing.T) {
		_, err := l.MarkRevoked("vc-1", "operator-b")
		if err == nil {
			t.Fatal("operator-b must not be able to revoke operator-a's credential")
		}
	})

	t.Run("unknown id is refused", func(t *testing.T) {
		if _, err := l.MarkRevoked("does-not-exist", "operator-a"); err == nil {
			t.Fatal("expected an error for an unknown id")
		}
	})

	t.Run("owner can revoke", func(t *testing.T) {
		got, err := l.MarkRevoked("vc-1", "operator-a")
		if err != nil {
			t.Fatalf("MarkRevoked: %v", err)
		}
		if got.RevokedAt == nil {
			t.Error("RevokedAt must be set after revocation")
		}
	})

	t.Run("state filter sees the revocation", func(t *testing.T) {
		if got := l.List(issuance.Filter{OwnerKey: "operator-a", State: "revoked"}); len(got) != 1 {
			t.Errorf("revoked filter returned %d rows, want 1", len(got))
		}
		if got := l.List(issuance.Filter{OwnerKey: "operator-a", State: "active"}); len(got) != 0 {
			t.Errorf("active filter returned %d rows, want 0", len(got))
		}
	})
}

func TestMarkReinstate_OwnerScoped(t *testing.T) {
	pool := testPool(t)
	l := NewIssuanceLog(pool)

	if _, err := l.Append(sample("vc-1", "Cedula")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.MarkRevoked("vc-1", "operator-a"); err != nil {
		t.Fatal(err)
	}

	if _, err := l.MarkReinstate("vc-1", "operator-b"); err == nil {
		t.Error("operator-b must not be able to reinstate operator-a's credential")
	}

	got, err := l.MarkReinstate("vc-1", "operator-a")
	if err != nil {
		t.Fatalf("MarkReinstate: %v", err)
	}
	if got.RevokedAt != nil {
		t.Error("RevokedAt must be cleared after reinstatement")
	}
}
