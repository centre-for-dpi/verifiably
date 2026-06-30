package handlers

import (
	"reflect"
	"testing"
)

func TestNormIdentityKey(t *testing.T) {
	cases := map[string]string{
		"given_name":   "givenname",
		"givenName":    "givenname",
		"given-name":   "givenname",
		"Given Name":   "givenname",
		"date_of_birth": "dateofbirth",
		"DOB":          "dob",
		"cédula":       "cdula", // accented rune is stripped (non-ASCII)
		"national_id":  "nationalid",
		"":             "",
	}
	for in, want := range cases {
		if got := normIdentityKey(in); got != want {
			t.Errorf("normIdentityKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentityPrefill(t *testing.T) {
	claims := map[string]string{
		"sub":         "user-1",
		"given_name":  "Ana",
		"family_name": "Pérez",
		"name":        "Ana Pérez",
		"birthdate":   "1990-05-01",
		"cedula":      "0801-1990-12345",
		"nationality": "GT",
		"email":       "", // empty claim must never be offered as prefill
	}

	tests := []struct {
		name   string
		fields []string
		claims map[string]string
		want   map[string]string
	}{
		{
			name:   "direct OIDC claim names",
			fields: []string{"given_name", "family_name", "birthdate"},
			claims: claims,
			want:   map[string]string{"given_name": "Ana", "family_name": "Pérez", "birthdate": "1990-05-01"},
		},
		{
			name:   "camelCase and snake_case both resolve",
			fields: []string{"givenName", "familyName"},
			claims: claims,
			want:   map[string]string{"givenName": "Ana", "familyName": "Pérez"},
		},
		{
			name:   "aliases: firstName/lastName/dateOfBirth/dob",
			fields: []string{"firstName", "lastName", "dateOfBirth", "dob"},
			claims: claims,
			want: map[string]string{
				"firstName": "Ana", "lastName": "Pérez",
				"dateOfBirth": "1990-05-01", "dob": "1990-05-01",
			},
		},
		{
			name:   "spanish field names",
			fields: []string{"nombre", "apellido", "fechaNacimiento", "nacionalidad"},
			claims: claims,
			want: map[string]string{
				"nombre": "Ana", "apellido": "Pérez",
				"fechaNacimiento": "1990-05-01", "nacionalidad": "GT",
			},
		},
		{
			name:   "national id aliases fall back across claim names",
			fields: []string{"nationalId", "dni", "documentNumber"},
			claims: claims,
			want: map[string]string{
				"nationalId": "0801-1990-12345", "dni": "0801-1990-12345",
				"documentNumber": "0801-1990-12345",
			},
		},
		{
			name:   "unmatched fields are omitted, not blanked",
			fields: []string{"favoriteColor", "given_name"},
			claims: claims,
			want:   map[string]string{"given_name": "Ana"},
		},
		{
			name:   "empty claim value is never offered",
			fields: []string{"email"},
			claims: claims,
			want:   nil,
		},
		{
			name:   "no claims yields nil (unauthenticated)",
			fields: []string{"given_name"},
			claims: nil,
			want:   nil,
		},
		{
			name:   "no fields yields nil",
			fields: nil,
			claims: claims,
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identityPrefill(tt.fields, tt.claims)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("identityPrefill(%v) = %v, want %v", tt.fields, got, tt.want)
			}
		})
	}
}
