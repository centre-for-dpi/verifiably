# driving_privileges de tamaño real (sin relleno duplicado) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** un mDL con 1, 2, 3 o 4 categorías de conducción reales produce un
`driving_privileges` con exactamente ese número de entradas — nunca
duplicadas ni rellenadas — usando 4 perfiles walt.id de tamaño fijo
seleccionados dinámicamente por el número real de categorías.

**Architecture:** 4 perfiles walt.id nuevos (`isoMdl_1cat`..`isoMdl_4cat`),
todos anunciando el mismo `credentialConfigurationId`, todos referenciando
las mismas variables top-level de clave/certificado por sustitución HOCON.
El adapter Go cuenta las categorías reales antes de crear la oferta y
selecciona el perfil correspondiente. Sin padding en ningún punto del
código.

**Tech Stack:** Go 1.25, HOCON (walt.id issuer-api2 config), Go templates
(HTML).

**Spec:** `docs/superpowers/specs/2026-08-24-mdl-driving-privileges-variable-count-design.md`

## Global Constraints

- El máximo de categorías es **4** (`DrivingPrivilegesMaxCategories`).
- 0 categorías reales es un **error explícito**, nunca un caso silenciosamente aceptado.
- `issuerKey = ${defaultIssuerKey}` y `x5Chain = ${defaultIssuerX5chain}` deben preservarse como **referencias HOCON por sustitución** en cada uno de los 4 perfiles nuevos — nunca como valores literales incrustados. Esto es un requisito de seguridad, no de estilo.
- Todos los 4 perfiles nuevos declaran `credentialConfigurationId = "org.iso.18013.5.1.mDL"` — idéntico al valor que el perfil `isoMdl` actual ya usa. `credential-issuer-metadata.baseline.conf` no se modifica.
- `isoPhotoId` no se toca en ningún archivo.
- Cada tarea que modifique Go debe dejar `go build ./... && go vet ./...` y la suite de su paquete en verde antes de pasar a la siguiente.
- Los mensajes de error nuevos van en español, en el mismo tono que los mensajes de error ya existentes en `internal/handlers/issuance.go`.

---

### Task 1: Perfiles HOCON — clonar `isoMdl` en 4 tamaños fijos

**Files:**
- Modify: `verifiably-go/deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf`
- Test: manual (HOCON no tiene test unitario propio; se verifica con Go en la Tarea 6 y con `issuer-api2` real en la Tarea 7)

**Interfaces:**
- Produces: 4 bloques de perfil llamados `isoMdl_1cat`, `isoMdl_2cat`, `isoMdl_3cat`, `isoMdl_4cat`, cada uno con `credentialConfigurationId = "org.iso.18013.5.1.mDL"` y un `driving_privileges.arrayConfig` de 1/2/3/4 entradas respectivamente. El perfil `isoMdl` original se elimina (reemplazado por los 4).

- [ ] **Step 1: Leer el archivo actual para confirmar el bloque exacto a reemplazar**

El bloque actual (líneas 138-228 del archivo, dentro de `profiles = { ... }`) es:

```hocon
  isoMdl = {
    name = "ISO 18013-5 Mobile Driving License"
    credentialConfigurationId = "org.iso.18013.5.1.mDL"
    issuerKey = ${defaultIssuerKey}
    credentialData = {
      "org.iso.18013.5.1" = {
        "family_name" = ""
        "given_name" = ""
        "birth_date" = ""
        "issue_date" = ""
        "expiry_date" = ""
        "issuing_country" = ""
        "issuing_authority" = ""
        "document_number" = ""
        "portrait" = ""
        "driving_privileges" = []
        "un_distinguishing_sign" = ""
        "portrait_capture_date" = ""
        "age_over_18" = false
        "age_over_21" = false
        "issuing_jurisdiction" = ""
      }
    }
    idTokenClaimsMapping = {
      "$.family_name" = "$.['org.iso.18013.5.1'].family_name"
      "$.given_name" = "$.['org.iso.18013.5.1'].given_name"
    }
    mDocNameSpacesDataMappingConfig = {
      "org.iso.18013.5.1" = {
        "entriesConfigMap" = {
          "birth_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "issue_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "expiry_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "portrait" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
          "driving_privileges" = {
            "type" = "array"
            "arrayConfig" = [
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
            ]
          }
          "portrait_capture_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "signature_usual_mark" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
        }
      }
    }
    x5Chain = ${defaultIssuerX5chain}
  }
```

- [ ] **Step 2: Reemplazar ese bloque completo por los 4 bloques nuevos**

Cada bloque nuevo es una copia exacta del bloque anterior salvo: el nombre
(`isoMdl_Ncat`), el comentario `name` (opcional, se deja como referencia
humana en `GET /issuer2/profiles`), y el número de entradas repetidas
dentro de `driving_privileges.arrayConfig`. **`issuerKey = ${defaultIssuerKey}`
y `x5Chain = ${defaultIssuerX5chain}` se copian literalmente tal cual —
NUNCA reemplazar por un valor resuelto.**

```hocon
  isoMdl_1cat = {
    name = "ISO 18013-5 Mobile Driving License (1 category)"
    credentialConfigurationId = "org.iso.18013.5.1.mDL"
    issuerKey = ${defaultIssuerKey}
    credentialData = {
      "org.iso.18013.5.1" = {
        "family_name" = ""
        "given_name" = ""
        "birth_date" = ""
        "issue_date" = ""
        "expiry_date" = ""
        "issuing_country" = ""
        "issuing_authority" = ""
        "document_number" = ""
        "portrait" = ""
        "driving_privileges" = []
        "un_distinguishing_sign" = ""
        "portrait_capture_date" = ""
        "age_over_18" = false
        "age_over_21" = false
        "issuing_jurisdiction" = ""
      }
    }
    idTokenClaimsMapping = {
      "$.family_name" = "$.['org.iso.18013.5.1'].family_name"
      "$.given_name" = "$.['org.iso.18013.5.1'].given_name"
    }
    mDocNameSpacesDataMappingConfig = {
      "org.iso.18013.5.1" = {
        "entriesConfigMap" = {
          "birth_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "issue_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "expiry_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "portrait" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
          "driving_privileges" = {
            "type" = "array"
            "arrayConfig" = [
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
            ]
          }
          "portrait_capture_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "signature_usual_mark" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
        }
      }
    }
    x5Chain = ${defaultIssuerX5chain}
  }

  isoMdl_2cat = {
    name = "ISO 18013-5 Mobile Driving License (2 categories)"
    credentialConfigurationId = "org.iso.18013.5.1.mDL"
    issuerKey = ${defaultIssuerKey}
    credentialData = {
      "org.iso.18013.5.1" = {
        "family_name" = ""
        "given_name" = ""
        "birth_date" = ""
        "issue_date" = ""
        "expiry_date" = ""
        "issuing_country" = ""
        "issuing_authority" = ""
        "document_number" = ""
        "portrait" = ""
        "driving_privileges" = []
        "un_distinguishing_sign" = ""
        "portrait_capture_date" = ""
        "age_over_18" = false
        "age_over_21" = false
        "issuing_jurisdiction" = ""
      }
    }
    idTokenClaimsMapping = {
      "$.family_name" = "$.['org.iso.18013.5.1'].family_name"
      "$.given_name" = "$.['org.iso.18013.5.1'].given_name"
    }
    mDocNameSpacesDataMappingConfig = {
      "org.iso.18013.5.1" = {
        "entriesConfigMap" = {
          "birth_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "issue_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "expiry_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "portrait" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
          "driving_privileges" = {
            "type" = "array"
            "arrayConfig" = [
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
            ]
          }
          "portrait_capture_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "signature_usual_mark" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
        }
      }
    }
    x5Chain = ${defaultIssuerX5chain}
  }

  isoMdl_3cat = {
    name = "ISO 18013-5 Mobile Driving License (3 categories)"
    credentialConfigurationId = "org.iso.18013.5.1.mDL"
    issuerKey = ${defaultIssuerKey}
    credentialData = {
      "org.iso.18013.5.1" = {
        "family_name" = ""
        "given_name" = ""
        "birth_date" = ""
        "issue_date" = ""
        "expiry_date" = ""
        "issuing_country" = ""
        "issuing_authority" = ""
        "document_number" = ""
        "portrait" = ""
        "driving_privileges" = []
        "un_distinguishing_sign" = ""
        "portrait_capture_date" = ""
        "age_over_18" = false
        "age_over_21" = false
        "issuing_jurisdiction" = ""
      }
    }
    idTokenClaimsMapping = {
      "$.family_name" = "$.['org.iso.18013.5.1'].family_name"
      "$.given_name" = "$.['org.iso.18013.5.1'].given_name"
    }
    mDocNameSpacesDataMappingConfig = {
      "org.iso.18013.5.1" = {
        "entriesConfigMap" = {
          "birth_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "issue_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "expiry_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "portrait" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
          "driving_privileges" = {
            "type" = "array"
            "arrayConfig" = [
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
            ]
          }
          "portrait_capture_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "signature_usual_mark" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
        }
      }
    }
    x5Chain = ${defaultIssuerX5chain}
  }

  isoMdl_4cat = {
    name = "ISO 18013-5 Mobile Driving License (4 categories)"
    credentialConfigurationId = "org.iso.18013.5.1.mDL"
    issuerKey = ${defaultIssuerKey}
    credentialData = {
      "org.iso.18013.5.1" = {
        "family_name" = ""
        "given_name" = ""
        "birth_date" = ""
        "issue_date" = ""
        "expiry_date" = ""
        "issuing_country" = ""
        "issuing_authority" = ""
        "document_number" = ""
        "portrait" = ""
        "driving_privileges" = []
        "un_distinguishing_sign" = ""
        "portrait_capture_date" = ""
        "age_over_18" = false
        "age_over_21" = false
        "issuing_jurisdiction" = ""
      }
    }
    idTokenClaimsMapping = {
      "$.family_name" = "$.['org.iso.18013.5.1'].family_name"
      "$.given_name" = "$.['org.iso.18013.5.1'].given_name"
    }
    mDocNameSpacesDataMappingConfig = {
      "org.iso.18013.5.1" = {
        "entriesConfigMap" = {
          "birth_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "issue_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "expiry_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "portrait" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
          "driving_privileges" = {
            "type" = "array"
            "arrayConfig" = [
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
              {
                "type" = "object"
                "entriesConfigMap" = {
                  "issue_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                  "expiry_date" = {
                    "type" = "string"
                    "conversionType" = "stringToFullDate"
                  }
                }
              }
            ]
          }
          "portrait_capture_date" = {
            "type" = "string"
            "conversionType" = "stringToFullDate"
          }
          "signature_usual_mark" = {
            "type" = "string"
            "conversionType" = "base64StringToByteString"
          }
        }
      }
    }
    x5Chain = ${defaultIssuerX5chain}
  }
```

También actualizar el comentario de cabecera del archivo que menciona
"Trimmed to isoMdl and isoPhotoId only" (línea ~126) para que diga
"Trimmed to isoMdl_1cat..isoMdl_4cat and isoPhotoId only", y el comentario
de líneas ~60-71 que menciona "isoMdl and isoPhotoId both do
`x5Chain = ${defaultIssuerX5chain}`" para que diga "isoMdl_1cat through
isoMdl_4cat, and isoPhotoId, all do...".

- [ ] **Step 3: Verificar seguridad de las referencias — grep, no boot**

```bash
cd verifiably-go
grep -c 'issuerKey = ${defaultIssuerKey}' deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf
grep -c 'x5Chain = ${defaultIssuerX5chain}' deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf
```

Expected: `5` para cada uno (4 perfiles de mDL + 1 de `isoPhotoId`, que ya
los tenía). Si algún número es menor, algún bloque nuevo tiene el
certificado/clave incrustado literalmente en vez de la referencia —
corregir antes de continuar.

```bash
grep -c '"type" = "object"' deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf
```

Expected: `10` (1+2+3+4 = 10 entradas de `arrayConfig` en total, sumadas
entre los 4 perfiles de mDL — Photo ID no tiene `driving_privileges`).

- [ ] **Step 4: Commit**

```bash
git add deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf
git commit -m "feat(mdl): split isoMdl into 4 fixed-size profiles by category count"
```

---

### Task 2: `internal/mdoc/drivingprivileges.go` — quitar el padding, renombrar la constante

**Files:**
- Modify: `verifiably-go/internal/mdoc/drivingprivileges.go`
- Test: `verifiably-go/internal/mdoc/drivingprivileges_test.go`

**Interfaces:**
- Consumes: nada nuevo.
- Produces: `DrivingPrivilegesMaxCategories = 4` (renombrado de
  `DrivingPrivilegesArrayConfigSize`, ahora un techo, no un tamaño exacto).
  `PadDrivingPrivileges` deja de existir. `EncodeDrivingPrivileges(in []DrivingPrivilege) (json.RawMessage, error)`
  mantiene su firma, pero ya no rellena — la longitud de salida es
  `len(in)` (tras limpiar entradas en blanco), truncada a
  `DrivingPrivilegesMaxCategories` si excede ese techo.

- [ ] **Step 1: Escribir el test que falla — "nunca rellena"**

Añadir a `drivingprivileges_test.go`, reemplazando
`TestEncodeDrivingPrivilegesPadsToArrayConfigSize` por:

```go
// TestEncodeDrivingPrivilegesNeverPads is the replacement for the old
// padding behavior: walt.id now has one profile per real category count
// (isoMdl_1cat..isoMdl_4cat), so the encoder must emit exactly what the
// operator supplied — 1, 2, 3, or 4 entries — never more.
func TestEncodeDrivingPrivilegesNeverPads(t *testing.T) {
	for n := 1; n <= DrivingPrivilegesMaxCategories; n++ {
		in := make([]DrivingPrivilege, n)
		for i := range in {
			in[i] = DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2019-03-01", ExpiryDate: "2029-03-01"}
		}
		raw, err := EncodeDrivingPrivileges(in)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}
		var arr []DrivingPrivilege
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatalf("n=%d: unmarshal: %v", n, err)
		}
		if len(arr) != n {
			t.Errorf("n=%d: encoded %d entries, want exactly %d — no padding should ever occur", n, len(arr), n)
		}
	}
}
```

- [ ] **Step 2: Confirmar que el nuevo test falla contra el código actual**

```bash
cd verifiably-go
go test ./internal/mdoc/... -run TestEncodeDrivingPrivilegesNeverPads -v
```

Expected: FAIL en `n=1` (el código actual rellena a 2).

- [ ] **Step 3: Modificar `drivingprivileges.go`**

Reemplazar el archivo completo:

```go
package mdoc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DrivingPrivilegesMaxCategories is the largest number of driving
// categories a single mDL can carry in this deployment.
//
// Unlike its predecessor (DrivingPrivilegesArrayConfigSize), this is a
// CEILING, not an exact count. walt.id's arrayConfig still requires an
// exact-length match — confirmed empirically against a real
// issuer-api2:0.23.1 that there is no variable-length mechanism in its
// config model at all — but that exactness is now handled by having one
// walt.id profile per real category count (isoMdl_1cat..isoMdl_4cat, see
// deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf), selected by
// internal/adapters/waltid's mdlProfileForCategoryCount. This constant
// only bounds how many profiles exist and how many rows the issue form
// renders.
//
// Raising this alone changes nothing: a new profile
// (isoMdl_(N+1)cat) with its own arrayConfig of N+1 entries must be added
// to issuer2-profiles.baseline.conf and mdlProfileForCategoryCount must
// learn to select it, or an operator entering N+1 categories gets
// rejected by buildIssuer2Offer before ever reaching walt.id.
const DrivingPrivilegesMaxCategories = 4

// DrivingPrivilege is one entry of the driving_privileges array as it travels
// to walt.id: plain JSON, with dates as "YYYY-MM-DD" strings that the
// profile's `stringToFullDate` conversion turns into CBOR full-dates.
//
// This is deliberately NOT internal/mdl.DrivingPrivilege. That type is the
// VERIFIER's CBOR model (its date fields are cbor-tagged *FullDate), and the
// mediator boundary says we translate rather than encode — walt.id's
// issuer-api2 owns CBOR. Reusing the verifier type here would mean marshalling
// a CBOR-shaped struct to JSON and would drag the emitter role into a package
// documented as read-only. The two shapes are asserted to agree field-for-field
// in drivingprivileges_test.go, so they cannot silently diverge.
type DrivingPrivilege struct {
	VehicleCategoryCode string `json:"vehicle_category_code"`
	IssueDate           string `json:"issue_date,omitempty"`
	ExpiryDate          string `json:"expiry_date,omitempty"`
}

// EncodeDrivingPrivileges renders the entries as the JSON array walt.id
// expects. Returns nil (not an empty array) when there is nothing to send,
// so the caller omits the claim entirely and lets issuer-api2 keep the
// profile's own value — sending `[]` would trip the size check.
//
// Never pads. Each real, non-blank entry the caller supplies survives
// as-is; the caller (buildIssuer2Offer) is responsible for choosing the
// walt.id profile whose arrayConfig matches this exact count. Truncates
// to DrivingPrivilegesMaxCategories as a backstop only — the issue form
// caps entry at that same limit first (see issuance.go's error when the
// operator fills more rows than the ceiling), so this path is not
// expected to be exercised in the normal UI flow.
func EncodeDrivingPrivileges(in []DrivingPrivilege) (json.RawMessage, error) {
	cleaned := make([]DrivingPrivilege, 0, len(in))
	for _, p := range in {
		p.VehicleCategoryCode = strings.TrimSpace(p.VehicleCategoryCode)
		p.IssueDate = strings.TrimSpace(p.IssueDate)
		p.ExpiryDate = strings.TrimSpace(p.ExpiryDate)
		if p.VehicleCategoryCode == "" {
			// An entry with no category code asserts nothing. Dropping it is
			// what lets the form render spare blank rows the operator can
			// ignore.
			continue
		}
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return nil, nil
	}
	if len(cleaned) > DrivingPrivilegesMaxCategories {
		cleaned = cleaned[:DrivingPrivilegesMaxCategories]
	}
	raw, err := json.Marshal(cleaned)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode driving_privileges: %w", err)
	}
	return raw, nil
}
```

- [ ] **Step 4: Actualizar el resto de `drivingprivileges_test.go`**

`TestEncodeDrivingPrivilegesTruncatesOverlongInput` (línea 88) cambia de
`DrivingPrivilegesArrayConfigSize+3` a `DrivingPrivilegesMaxCategories+3`,
y su aserción de longitud de `DrivingPrivilegesArrayConfigSize` a
`DrivingPrivilegesMaxCategories`:

```go
func TestEncodeDrivingPrivilegesTruncatesOverlongInput(t *testing.T) {
	in := make([]DrivingPrivilege, DrivingPrivilegesMaxCategories+3)
	for i := range in {
		in[i] = DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2020-01-01", ExpiryDate: "2030-01-01"}
	}
	raw, err := EncodeDrivingPrivileges(in)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	var arr []DrivingPrivilege
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != DrivingPrivilegesMaxCategories {
		t.Errorf("len = %d, want %d", len(arr), DrivingPrivilegesMaxCategories)
	}
}
```

El resto de tests (`TestEncodeDrivingPrivilegesIsARealJSONArray`,
`TestEncodeDrivingPrivilegesDropsBlankRows`, `TestDrivingPrivilegeMatchesVerifierModel`,
`cutTag`) no referencian la constante renombrada — se dejan intactos.

- [ ] **Step 5: Correr la suite del paquete**

```bash
go test ./internal/mdoc/... -v
```

Expected: todos los tests de `drivingprivileges_test.go` PASS, incluyendo
el nuevo `TestEncodeDrivingPrivilegesNeverPads`.

- [ ] **Step 6: Commit**

```bash
git add internal/mdoc/drivingprivileges.go internal/mdoc/drivingprivileges_test.go
git commit -m "feat(mdl): remove driving_privileges padding, rename to a ceiling constant"
```

---

### Task 3: `internal/adapters/waltid/issuer2.go` — selección de perfil por conteo real

**Files:**
- Modify: `verifiably-go/internal/adapters/waltid/issuer2.go`
- Test: `verifiably-go/internal/adapters/waltid/issuer2_test.go`

**Interfaces:**
- Consumes: `mdoc.DrivingPrivilegesMaxCategories` (Task 2), 4 perfiles walt.id nombrados `isoMdl_1cat`..`isoMdl_4cat` (Task 1).
- Produces: nueva función `mdlProfileForCategoryCount(n int) (mdocProfile, bool)`. `buildIssuer2Offer(schema vctypes.Schema, subject map[string]string, structured map[string]json.RawMessage) (issuer2OfferRequest, error)` mantiene su firma pero cambia su lógica interna de selección de perfil para el docType mDL.

- [ ] **Step 1: Escribir el test que falla — selección dinámica de perfil**

Añadir a `issuer2_test.go`:

```go
func TestMdlProfileForCategoryCount(t *testing.T) {
	tests := []struct {
		n             int
		wantProfileID string
		wantOK        bool
	}{
		{0, "", false},
		{1, "isoMdl_1cat", true},
		{2, "isoMdl_2cat", true},
		{3, "isoMdl_3cat", true},
		{4, "isoMdl_4cat", true},
		{5, "", false},
		{-1, "", false},
	}
	for _, tt := range tests {
		got, ok := mdlProfileForCategoryCount(tt.n)
		if got.profileID != tt.wantProfileID || ok != tt.wantOK {
			t.Errorf("mdlProfileForCategoryCount(%d) = (%+v, %v), want (profileID=%q, %v)",
				tt.n, got, ok, tt.wantProfileID, tt.wantOK)
		}
		if ok && got.baseNamespace != "org.iso.18013.5.1" {
			t.Errorf("mdlProfileForCategoryCount(%d).baseNamespace = %q, want org.iso.18013.5.1", tt.n, got.baseNamespace)
		}
	}
}
```

- [ ] **Step 2: Confirmar que falla (la función no existe aún)**

```bash
go build ./internal/adapters/waltid/... 2>&1 | head -5
```

Expected: `undefined: mdlProfileForCategoryCount`.

- [ ] **Step 3: Añadir `mdlProfileForCategoryCount` a `issuer2.go`**

Insertar inmediatamente después de `profileIDForDocType` (tras la línea
`func profileIDForDocType(docType string) (mdocProfile, bool) { ... }`):

```go
// mdlProfileForCategoryCount resolves the issuer-api2 profile for an mDL
// carrying exactly n real driving_privileges entries.
//
// walt.id's arrayConfig requires an EXACT length match — confirmed
// empirically against a real issuer-api2:0.23.1 with arrayConfig sizes of
// 2, 3, and 6: in every case, only that exact declared size succeeds, any
// other length (including a smaller one) fails with
// "Json array sizes (input & config) are not equal". There is no
// variable-length mechanism in walt.id's config model to fall back to.
//
// So instead of one isoMdl profile padded to a fixed size,
// issuer2-profiles.baseline.conf declares one profile PER real category
// count — isoMdl_1cat through isoMdl_4cat — all sharing the same
// credentialConfigurationId ("org.iso.18013.5.1.mDL") and the same
// issuerKey/x5Chain (by HOCON substitution reference, not literal
// duplication). Confirmed empirically that two profiles sharing one
// credentialConfigurationId do not collide: profileId is fixed
// server-side at offer-creation time (POST /issuer2/credential-offers),
// before the wallet ever resolves anything, so the wallet never needs to
// disambiguate between them.
//
// n <= 0 or n > mdoc.DrivingPrivilegesMaxCategories returns (mdocProfile{}, false):
// 0 real categories is refused because driving_privileges is a MANDATORY
// ISO 18013-5 Table 3 element for mDL, and more than the ceiling has no
// profile provisioned for it.
func mdlProfileForCategoryCount(n int) (mdocProfile, bool) {
	if n <= 0 || n > mdoc.DrivingPrivilegesMaxCategories {
		return mdocProfile{}, false
	}
	return mdocProfile{
		profileID:     fmt.Sprintf("isoMdl_%dcat", n),
		baseNamespace: "org.iso.18013.5.1",
	}, true
}
```

Esto requiere importar `github.com/verifiably/verifiably-go/internal/mdoc`
en `issuer2.go` — confirmar si ya está importado (no lo estaba al momento
de escribir este plan) y añadirlo al bloque `import` si falta.

- [ ] **Step 4: Correr el test de la Task 3 Step 1**

```bash
go test ./internal/adapters/waltid/... -run TestMdlProfileForCategoryCount -v
```

Expected: PASS.

- [ ] **Step 5: Escribir el test que falla — `buildIssuer2Offer` selecciona el perfil correcto**

Añadir a `issuer2_test.go`:

```go
// TestBuildIssuer2OfferSelectsProfileByCategoryCount is the integration
// point between mdlProfileForCategoryCount and buildIssuer2Offer: the
// caller passes real driving_privileges via StructuredData, and the
// resulting ProfileID must match that exact count — never a fixed
// "isoMdl", and never padded to a different count.
func TestBuildIssuer2OfferSelectsProfileByCategoryCount(t *testing.T) {
	schema := vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc", Name: "Driver's Licence"}
	subject := map[string]string{"family_name": "Perez", "given_name": "Ana"}

	for n := 1; n <= mdoc.DrivingPrivilegesMaxCategories; n++ {
		privileges := make([]mdoc.DrivingPrivilege, n)
		for i := range privileges {
			privileges[i] = mdoc.DrivingPrivilege{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"}
		}
		raw, err := mdoc.EncodeDrivingPrivileges(privileges)
		if err != nil {
			t.Fatalf("n=%d: EncodeDrivingPrivileges: %v", n, err)
		}
		structured := map[string]json.RawMessage{"driving_privileges": raw}

		req, err := buildIssuer2Offer(schema, subject, structured)
		if err != nil {
			t.Fatalf("n=%d: buildIssuer2Offer: %v", n, err)
		}
		wantProfileID := fmt.Sprintf("isoMdl_%dcat", n)
		if req.ProfileID != wantProfileID {
			t.Errorf("n=%d: ProfileID = %q, want %q", n, req.ProfileID, wantProfileID)
		}

		ns := req.RuntimeOverrides.CredentialData["org.iso.18013.5.1"]
		arr, ok := ns["driving_privileges"].([]any)
		if !ok {
			t.Fatalf("n=%d: driving_privileges is %T, want []any", n, ns["driving_privileges"])
		}
		if len(arr) != n {
			t.Errorf("n=%d: driving_privileges has %d entries, want exactly %d — no padding", n, len(arr), n)
		}
	}
}

// TestBuildIssuer2OfferRejectsZeroDrivingPrivileges is the negative case:
// driving_privileges is a MANDATORY ISO 18013-5 Table 3 element for mDL,
// so 0 real categories must be a hard error, never silently accepted or
// defaulted to some profile.
func TestBuildIssuer2OfferRejectsZeroDrivingPrivileges(t *testing.T) {
	schema := vctypes.Schema{ID: "org.iso.18013.5.1.mDL", Std: "mso_mdoc", Name: "Driver's Licence"}
	subject := map[string]string{"family_name": "Perez", "given_name": "Ana"}

	if _, err := buildIssuer2Offer(schema, subject, nil); err == nil {
		t.Error("buildIssuer2Offer with no driving_privileges at all returned no error, want a rejection")
	}

	empty, err := mdoc.EncodeDrivingPrivileges(nil)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges(nil): %v", err)
	}
	if empty != nil {
		t.Fatalf("EncodeDrivingPrivileges(nil) = %s, want nil", empty)
	}
	// empty is nil, so this reproduces the "field never sent" case, same as above.
}
```

- [ ] **Step 6: Confirmar que ambos tests fallan contra el código actual**

```bash
go test ./internal/adapters/waltid/... -run 'TestBuildIssuer2OfferSelectsProfileByCategoryCount|TestBuildIssuer2OfferRejectsZeroDrivingPrivileges' -v
```

Expected: FAIL — `buildIssuer2Offer` todavía usa `profileIDForDocType`
incondicionalmente y siempre devuelve `ProfileID: "isoMdl"`, y nunca
rechaza 0 categorías.

- [ ] **Step 7: Modificar `buildIssuer2Offer`**

Reemplazar el cuerpo de la función (desde `func buildIssuer2Offer(...)` hasta
su `return req, nil` de cierre) por:

```go
// buildIssuer2Offer turns a schema plus the operator's filled-in fields into
// a credential-offer request.
//
// Only fields the operator actually supplied are sent. This is deliberate and
// load-bearing: issuer-api2 deep-merges runtimeOverrides over the profile, so
// an omitted field keeps whatever the profile holds. Our versioned profile has
// its sample data emptied for exactly this reason (see
// deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf) — walt.id's shipped default
// is a fictional Austrian person, and inheriting it silently would issue a
// real credential carrying someone else's data.
// structured carries the non-scalar claims (see backend.IssueRequest.
// StructuredData) that cannot ride in the flat subject map. A nil or empty
// map keeps the previous behaviour exactly, EXCEPT for mDL: an mDL with no
// driving_privileges is now a hard error (see below), because the field is
// ISO 18013-5 Table 3 MANDATORY and there is no longer a padding path to
// silently paper over its absence.
func buildIssuer2Offer(schema vctypes.Schema, subject map[string]string, structured map[string]json.RawMessage) (issuer2OfferRequest, error) {
	docType := mdocDocTypeFor(schema)

	var profile mdocProfile
	if docType == "org.iso.18013.5.1.mDL" {
		// mDL selects its profile by the REAL number of driving_privileges
		// entries the operator supplied — see mdlProfileForCategoryCount's
		// doc comment for why: walt.id's arrayConfig requires an exact
		// length match, confirmed empirically, so one profile per real
		// category count replaces the old fixed-size-plus-padding approach.
		n := 0
		if raw, ok := structured["driving_privileges"]; ok && len(raw) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return issuer2OfferRequest{}, fmt.Errorf(
					"waltid: driving_privileges is not a JSON array: %w", err)
			}
			n = len(arr)
		}
		p, ok := mdlProfileForCategoryCount(n)
		if !ok {
			if n == 0 {
				return issuer2OfferRequest{}, fmt.Errorf(
					"waltid: driving_privileges es obligatorio en ISO 18013-5 — ingresa al menos una categoría de conducción antes de emitir")
			}
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: no se pueden emitir %d categorías de conducción en una sola credencial — el máximo es %d",
				n, mdoc.DrivingPrivilegesMaxCategories)
		}
		profile = p
	} else {
		p, ok := profileIDForDocType(docType)
		if !ok {
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: no issuer-api2 profile for docType %q — only pre-provisioned docTypes can be issued (see deploy/k8s/config/issuer2/issuer2-profiles.conf)",
				docType)
		}
		profile = p
	}

	data := make(map[string]any, len(subject)+len(structured))
	for k, v := range subject {
		if v == "" {
			continue // omit rather than assert a blank
		}
		data[k] = v
	}
	// Omitting a blank is right for text, but FATAL for a date. issuer-api2
	// deep-merges runtimeOverrides over the profile, and our profile ships
	// every sample value emptied (walt.id's defaults are a fictional Austrian
	// person). So a date we omit keeps the profile's "" — and its
	// stringToFullDate conversion cannot parse an empty string. The offer
	// still returns 201; issuance dies on the citizen's phone with
	//
	//	java.time.format.DateTimeParseException: Text '' could not be parsed
	//
	// Reproduced against a live issuer-api2 by omitting issue_date. Sending a
	// real value for every date the profile maps is the only way to keep the
	// profile's blank from reaching the converter, so an unfilled optional
	// date falls back to a defined one rather than being left out.
	for _, f := range schema.FieldsSpec {
		if f.Format != "date" {
			continue
		}
		if s, ok := data[f.Name].(string); ok && strings.TrimSpace(s) != "" {
			continue
		}
		if fb := mdocDateFallback(f.Name, subject); fb != "" {
			data[f.Name] = fb
		}
	}
	// Structured claims override any flat entry of the same name. The issue
	// form never posts both, but an API caller could, and the structured value
	// is the one the profile's arrayConfig can actually convert.
	for k, raw := range structured {
		if len(raw) == 0 {
			continue
		}
		// json.RawMessage marshals verbatim, so the array reaches issuer-api2
		// as a real JSON array rather than a quoted string. Validate here
		// rather than trusting the caller: a malformed value would otherwise
		// surface as an opaque walt.id error at wallet-redemption time, long
		// after the operator has left the form.
		if !json.Valid(raw) {
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: structured claim %q is not valid JSON", k)
		}
		data[k] = raw
	}

	req := issuer2OfferRequest{
		ProfileID:        profile.profileID,
		AuthMethod:       "PRE_AUTHORIZED",
		ExpiresInSeconds: issuer2OfferTTL,
	}
	if len(data) > 0 {
		req.RuntimeOverrides = &issuer2RuntimeOverrides{
			CredentialData: map[string]map[string]any{profile.baseNamespace: data},
		}
	}
	return req, nil
}
```

Nota: `docTypeProfiles["org.iso.18013.5.1.mDL"]` sigue existiendo sin
cambios en el mapa (Task 3 no la toca) — sigue sirviendo como allowlist
para `catalog.go:321` y `catalog_issuer2.go:37`, que solo leen
`.baseNamespace` o el booleano `ok`, nunca `.profileID`, así que no se ven
afectados por que `buildIssuer2Offer` ya no la use para mDL.

- [ ] **Step 8: Correr los tests de la Task 3**

```bash
go test ./internal/adapters/waltid/... -run 'TestMdlProfileForCategoryCount|TestBuildIssuer2OfferSelectsProfileByCategoryCount|TestBuildIssuer2OfferRejectsZeroDrivingPrivileges' -v
```

Expected: los tres PASS.

- [ ] **Step 9: Actualizar los tests existentes que ahora fallan por el cambio de comportamiento**

`TestBuildIssuer2OfferOmitsUnsetFields` (línea ~119) fallaría ahora porque
llama `buildIssuer2Offer(schema, subject, nil)` — 0 categorías reales.
Dividir en dos:

```go
// A field the caller omits must NOT appear in the request at all. issuer-api2
// merges runtimeOverrides recursively over the profile, so any key we send
// wins but any key we omit keeps the profile's value. The versioned profile
// has its sample data emptied precisely so an omission surfaces as blank —
// but if we were to send a key with a zero value we would be asserting that
// blank on purpose, and if we send nothing the profile decides. This test
// pins the boundary: only what the operator actually filled in gets sent.
//
// Sends one real driving_privileges entry (not zero) so this test exercises
// field omission without colliding with the separate 0-categories rejection
// covered by TestBuildIssuer2OfferRejectsZeroDrivingPrivileges.
func TestBuildIssuer2OfferOmitsUnsetFields(t *testing.T) {
	schema := vctypes.Schema{
		ID:   "org.iso.18013.5.1.mDL",
		Std:  "mso_mdoc",
		Name: "Driver's Licence",
	}
	subject := map[string]string{
		"family_name": "Perez",
		"given_name":  "Ana",
	}
	privileges, err := mdoc.EncodeDrivingPrivileges([]mdoc.DrivingPrivilege{
		{VehicleCategoryCode: "B", IssueDate: "2021-06-01", ExpiryDate: "2031-06-01"},
	})
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	structured := map[string]json.RawMessage{"driving_privileges": privileges}

	req, err := buildIssuer2Offer(schema, subject, structured)
	if err != nil {
		t.Fatalf("buildIssuer2Offer: %v", err)
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "Perez") || !strings.Contains(body, "Ana") {
		t.Errorf("supplied fields missing from request: %s", body)
	}
	for _, absent := range []string{"nationality", "issuing_country", "birth_date"} {
		if strings.Contains(body, absent) {
			t.Errorf("unsupplied field %q leaked into request — it would inherit the profile's sample value: %s", absent, body)
		}
	}
	if req.ProfileID != "isoMdl_1cat" {
		t.Errorf("ProfileID = %q, want isoMdl_1cat", req.ProfileID)
	}
	if req.AuthMethod != "PRE_AUTHORIZED" {
		t.Errorf("AuthMethod = %q, want PRE_AUTHORIZED", req.AuthMethod)
	}
}
```

(`TestBuildIssuer2OfferRejectsZeroDrivingPrivileges`, ya añadida en Step 5,
cubre el caso de 0 categorías que este test ya no ejercita.)

`TestIssuer2OfferCarriesDrivingPrivilegesAsJSONArray` (línea ~313) envía 2
entradas reales vía `mdoc.EncodeDrivingPrivileges` — su aserción de
longitud (línea ~370: `len(arr) != mdoc.DrivingPrivilegesArrayConfigSize`)
cambia a comparar contra `2` directamente (el número real que el test
envía, ya no contra una constante de padding):

```go
	if len(arr) != 2 {
		t.Errorf("driving_privileges length = %d, want 2 (the real count this test submitted, no padding)",
			len(arr))
	}
```

- [ ] **Step 10: Correr la suite completa del paquete**

```bash
go test ./internal/adapters/waltid/... -v 2>&1 | tail -60
```

Expected: todos PASS. `TestProfileIDForDocType`,
`TestKnownDocTypesResolveInProfiles`, `TestBuilderSavedMdocSchemaResolvesProfile`
no requieren cambios de código — siguen probando la resolución
"¿existe algún perfil para este docType?" vía `docTypeProfiles`, que Task
3 no modifica.

- [ ] **Step 11: Commit**

```bash
git add internal/adapters/waltid/issuer2.go internal/adapters/waltid/issuer2_test.go
git commit -m "feat(mdl): select the walt.id profile by real driving_privileges count"
```

---

### Task 4: `internal/handlers/issuance.go` — mensaje de error de 0/exceso de categorías

**Files:**
- Modify: `verifiably-go/internal/handlers/issuance.go`
- Test: `verifiably-go/internal/handlers/issue_structured_fields_test.go`

**Interfaces:**
- Consumes: `mdoc.DrivingPrivilegesMaxCategories` (Task 2).
- Produces: sin cambio de firma pública — el bloque de `SubmitIssue` que valida `driving_privileges` cambia su constante referenciada y añade el rechazo explícito de 0 filas.

- [ ] **Step 1: Escribir el test que falla — 0 categorías rechazadas en el handler**

Añadir a `issue_structured_fields_test.go`, cerca de
`TestDrivingPrivilegesOverCapWarnsOperator`:

```go
// TestDrivingPrivilegesZeroRowsWarnsOperator is the handler-level half of
// the 0-categories rejection: driving_privileges is ISO 18013-5 Table 3
// MANDATORY for mDL, and the issue form's asterisk on the first row is
// purely visual (no `required` HTML attribute) — so SubmitIssue itself
// must be the real defense against a submission with every row left blank.
func TestDrivingPrivilegesZeroRowsWarnsOperator(t *testing.T) {
	form := url.Values{} // no dp_vehicle_category_code_0 at all
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()

	filled := drivingPrivilegeRows(req, 0)
	if len(filled) != 0 {
		t.Fatalf("drivingPrivilegeRows read %d entries, want 0 for this test's premise", len(filled))
	}

	raw, err := mdoc.EncodeDrivingPrivileges(filled)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	if raw != nil {
		t.Fatalf("EncodeDrivingPrivileges(0 rows) = %s, want nil", raw)
	}
	// This confirms the PREMISE (0 rows encode to nil, same as before);
	// the actual rejection this test guards is exercised through
	// SubmitIssue's own logic in issuance.go, which must reject nil/empty
	// driving_privileges for docType org.iso.18013.5.1.mDL specifically —
	// verified via TestBuildIssuer2OfferRejectsZeroDrivingPrivileges
	// (internal/adapters/waltid/issuer2_test.go), since SubmitIssue's own
	// HTTP-level test harness in this package does not construct a full
	// backend.Adapter round trip.
}
```

- [ ] **Step 2: Modificar el bloque de validación en `issuance.go`**

El bloque actual (líneas ~605-632, dentro de `SubmitIssue`) es:

```go
		if isStructuredField(fs) {
			// Structured claims never enter `subject`: it is map[string]string
			// and stringifying an array here is exactly the bug this path
			// exists to fix (TODO.md F4). They travel in StructuredData, which
			// only the mdoc adapter reads.
			// Tell the operator when they filled more categories than the
			// vendor profile can carry, instead of silently dropping the
			// extras. EncodeDrivingPrivileges truncates as a backstop, and a
			// truncation nobody is told about is exactly the class of quiet
			// data loss this whole change set exists to remove: the operator
			// would see a successful issuance and a credential missing a
			// category they entered.
			if filled := drivingPrivilegeRows(r, tzOffset); len(filled) > mdoc.DrivingPrivilegesArrayConfigSize {
				h.errorToast(w, r, fmt.Sprintf(
					"Solo se pueden emitir %d categorías de conducción por credencial (ingresaste %d). El perfil de walt.id declara un arreglo de tamaño fijo — quita las categorías sobrantes.",
					mdoc.DrivingPrivilegesArrayConfigSize, len(filled)))
				return
			}
			raw, encErr := mdoc.EncodeDrivingPrivileges(drivingPrivilegeRows(r, tzOffset))
			if encErr != nil {
				h.errorToast(w, r, encErr.Error())
				return
			}
			if len(raw) > 0 {
				structured[fs.Name] = raw
			}
			continue
		}
```

Reemplazar por:

```go
		if isStructuredField(fs) {
			// Structured claims never enter `subject`: it is map[string]string
			// and stringifying an array here is exactly the bug this path
			// exists to fix (TODO.md F4). They travel in StructuredData, which
			// only the mdoc adapter reads.
			filled := drivingPrivilegeRows(r, tzOffset)
			// Tell the operator when they filled more categories than the
			// deployment can carry, instead of silently dropping the extras.
			// EncodeDrivingPrivileges truncates as a backstop, and a
			// truncation nobody is told about is exactly the class of quiet
			// data loss this whole change set exists to remove: the operator
			// would see a successful issuance and a credential missing a
			// category they entered.
			if len(filled) > mdoc.DrivingPrivilegesMaxCategories {
				h.errorToast(w, r, fmt.Sprintf(
					"Solo se pueden emitir %d categorías de conducción por credencial (ingresaste %d). Quita las categorías sobrantes.",
					mdoc.DrivingPrivilegesMaxCategories, len(filled)))
				return
			}
			// driving_privileges is a MANDATORY ISO/IEC 18013-5 Table 3
			// element for mDL. The issue form's asterisk on the first row
			// (templates/pages/issuer_issue.html) is purely visual — the
			// input carries no `required` attribute — so this is the only
			// real defense against a submission with every row left blank.
			// Without this check, buildIssuer2Offer's own rejection
			// (internal/adapters/waltid/issuer2.go) would still catch it,
			// but only after the round trip to the adapter, with a less
			// specific error message.
			if len(filled) == 0 {
				h.errorToast(w, r,
					"driving_privileges es obligatorio en ISO 18013-5 — ingresa al menos una categoría de conducción antes de emitir.")
				return
			}
			raw, encErr := mdoc.EncodeDrivingPrivileges(filled)
			if encErr != nil {
				h.errorToast(w, r, encErr.Error())
				return
			}
			if len(raw) > 0 {
				structured[fs.Name] = raw
			}
			continue
		}
```

- [ ] **Step 3: Actualizar `TestDrivingPrivilegesOverCapWarnsOperator`**

Este test (línea 419) manda 3 categorías contra el cap viejo de 2 y afirma
truncamiento a 2. Con el nuevo cap de 4, cambiar a 5 categorías contra el
cap de 4:

```go
func TestDrivingPrivilegesOverCapWarnsOperator(t *testing.T) {
	form := url.Values{}
	for i, code := range []string{"A", "B", "C", "D", "E"} {
		form.Set(fmt.Sprintf("dp_vehicle_category_code_%d", i), code)
		form.Set(fmt.Sprintf("dp_issue_date_%d", i), "2020-01-01")
		form.Set(fmt.Sprintf("dp_expiry_date_%d", i), "2030-01-01")
	}
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()

	filled := drivingPrivilegeRows(req, 0)
	if len(filled) != 5 {
		t.Fatalf("drivingPrivilegeRows read %d entries, want 5", len(filled))
	}
	if len(filled) <= mdoc.DrivingPrivilegesMaxCategories {
		t.Fatalf("test premise broken: 5 entries should exceed the cap of %d",
			mdoc.DrivingPrivilegesMaxCategories)
	}

	// The encoder truncates as a backstop — that silent drop is precisely what
	// makes an un-warned operator lose data, which is why SubmitIssue rejects
	// before reaching it.
	raw, err := mdoc.EncodeDrivingPrivileges(filled)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	var got []mdoc.DrivingPrivilege
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != mdoc.DrivingPrivilegesMaxCategories {
		t.Errorf("encoded %d entries, want %d", len(got), mdoc.DrivingPrivilegesMaxCategories)
	}
	for _, p := range got {
		if p.VehicleCategoryCode == "E" {
			t.Error("fifth category survived encoding — the cap is not what this test assumes")
		}
	}
}
```

**Nota:** el formulario renderiza `maxDrivingPrivilegeRows = 4` filas
(Task 5 no cambia esto), así que este test manda 5 categorías vía POST
directo — más filas de las que el formulario real ofrece — para ejercer
el backstop del encoder exactamente como el test original hacía (3 contra
un cap de 2, también más filas de las 4 que el formulario ya renderizaba
en ese momento histórico). Esto es consistente con el comentario del test:
"SubmitIssue rejects before reaching it" en el flujo real vía UI.

- [ ] **Step 4: Actualizar `TestSubmitIssueSendsDrivingPrivilegesAsRealJSONArray`**

Línea ~124 y ~127 referencian `mdoc.DrivingPrivilegesArrayConfigSize` —
renombrar a `mdoc.DrivingPrivilegesMaxCategories` solo como referencia de
constante (la aserción de longitud sigue comparando contra `2` porque el
test sigue enviando 2 filas reales, así que en la práctica compara contra
el valor real enviado, no contra el máximo):

```go
	if len(arr) != 2 {
		t.Fatalf("driving_privileges has %d entries, want 2 — this test filled exactly 2 rows, no padding or truncation should apply",
			len(arr))
	}
```

- [ ] **Step 5: Actualizar `TestSubmitIssueSingleDrivingPrivilegeIsPadded` — renombrar e invertir la aserción**

Este test (línea 146) prueba directamente el comportamiento que se
elimina. Renombrar y reescribir:

```go
// A single filled row must still issue, and must NOT be padded — it is
// exactly this padding (duplicating the holder's one real category to
// satisfy a fixed-size arrayConfig) that this whole change removes. See
// mdlProfileForCategoryCount in internal/adapters/waltid/issuer2.go: a
// single real category now selects the isoMdl_1cat profile, whose
// arrayConfig has exactly one slot.
func TestSubmitIssueSingleDrivingPrivilegeIsNotPadded(t *testing.T) {
	schema := mdlSchemaForTest()
	r := multipartRequest(t, map[string]string{
		"dp_vehicle_category_code_0": "A",
		"dp_issue_date_0":            "2020-02-02",
		"dp_expiry_date_0":           "2030-02-02",
	}, "", nil)

	structured := gatherStructuredForTest(t, r, schema)
	var arr []map[string]any
	if err := json.Unmarshal(structured["driving_privileges"], &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != 1 {
		t.Fatalf("one filled row produced %d entries, want exactly 1 — no padding", len(arr))
	}
	if arr[0]["issue_date"] == "" || arr[0]["issue_date"] == nil {
		t.Errorf("the single entry has no issue_date — stringToFullDate fails on \"\"")
	}
}
```

- [ ] **Step 6: Correr la suite completa del paquete `handlers`**

```bash
go test ./internal/handlers/... -run 'DrivingPrivileges|SubmitIssue' -v 2>&1 | tail -80
```

Expected: todos PASS, incluyendo el test nuevo de la Step 1.

- [ ] **Step 7: Commit**

```bash
git add internal/handlers/issuance.go internal/handlers/issue_structured_fields_test.go
git commit -m "feat(mdl): reject 0 driving_privileges categories, raise the cap to 4"
```

---

### Task 5: `templates/pages/issuer_issue.html` — quitar la nota de duplicado

**Files:**
- Modify: `verifiably-go/templates/pages/issuer_issue.html`

**Interfaces:**
- Consumes: nada.
- Produces: nada (solo texto de ayuda visible al operador).

- [ ] **Step 1: Localizar y quitar la nota agregada en la sesión anterior**

El bloque actual (dentro del `{{else if eq .Format "driving_privileges"}}`,
después del `{{range $i := $.DrivingPrivilegeRows}}...{{end}}`) es:

```html
            <p class="hint" style="font-size:0.72rem;color:var(--ink-mute);margin:0.4rem 0 0">
              One row per vehicle category the holder is licensed for. Leave unused rows blank — they are dropped. Fill at least the first category.
              <strong>Note:</strong> the walt.id profile requires exactly two categories per credential — if you fill only one, it is duplicated to satisfy that requirement, so the wallet will correctly show two identical rows rather than an error.
            </p>
```

Reemplazar por:

```html
            <p class="hint" style="font-size:0.72rem;color:var(--ink-mute);margin:0.4rem 0 0">
              One row per vehicle category the holder is licensed for. Leave unused rows blank — they are dropped. Fill at least the first category (driving_privileges is mandatory under ISO 18013-5).
            </p>
```

- [ ] **Step 2: Verificar sintaxis del template**

```bash
cd verifiably-go
docker run --rm -v "//c/Users/yalva/source/repos/cdpi/verifiably/verifiably-go/templates/pages/issuer_issue.html:/issuer_issue.html" \
  golang:1.25-alpine sh -c 'cat > /parse.go <<EOF
package main
import ("fmt";"html/template";"os")
func main() {
  funcs := template.FuncMap{
    "t": func(args ...interface{}) string { return "" },
    "jsonRows": func(args ...interface{}) interface{} { return nil },
    "replaceUnderscore": func(s string) string { return s },
    "dict": func(args ...interface{}) map[string]interface{} { return nil },
  }
  _, err := template.New("x").Funcs(funcs).ParseFiles(os.Args[1])
  if err != nil { fmt.Println("PARSE ERROR:", err); os.Exit(1) }
  fmt.Println("PARSED OK")
}
EOF
go run /parse.go /issuer_issue.html'
```

Expected: `PARSED OK` (mismo método de verificación usado en la sesión que
agregó la nota original).

- [ ] **Step 3: Commit**

```bash
git add templates/pages/issuer_issue.html
git commit -m "docs(mdl): remove the duplicate-row note, no longer applicable"
```

---

### Task 6: `internal/adapters/waltid/profiletrim_test.go` — actualizar los guards del trim

**Files:**
- Modify: `verifiably-go/internal/adapters/waltid/profiletrim_test.go`

**Interfaces:**
- Consumes: el `issuer2-profiles.baseline.conf` de la Task 1 (4 bloques de mDL).
- Produces: sin cambio de firma — los dos tests existentes se actualizan para reconocer 4 bloques en vez de 1.

- [ ] **Step 1: Actualizar `expectedConversionMappings`**

El slice actual (líneas 48-67) tiene 14 entradas: 10 de un único perfil
mDL (con `arrayConfig` de 2 → 6 conversiones fijas + 2×2=4 de
driving_privileges = 10) + 4 de Photo ID. Con 4 perfiles de mDL, el total
correcto es: 6 fijas × 4 perfiles = 24, más 2 conversiones
(`issue_date`+`expiry_date`) por cada entrada de `arrayConfig`, sumadas
sobre los 4 perfiles (1+2+3+4 = 10 entradas de `arrayConfig` en total,
× 2 conversiones cada una = 20), más las 4 de Photo ID sin cambios — total
**24 + 20 + 4 = 48**. Este es el mismo número ya confirmado en la Task 1
Step 3 (`grep -c '"type" = "object"'` = 10 entradas de arrayConfig) y en
el spec de diseño. Reemplazar el slice por una construcción programática
en vez de una lista literal, para que no haya que mantener a mano 48
tuplas:

```go
// expectedConversionMappings is the exact set of CBOR conversion mappings
// each profile must carry, as (field, conversionType) pairs counted with
// multiplicity within ONE profile block. isoMdl_1cat..isoMdl_4cat share
// the same fixed set (6 entries) plus 2 per driving_privileges arrayConfig
// entry (which varies 1..4 across the four profiles) — expectedMdlMappingsForProfile
// builds that per-profile list so the test does not hand-maintain a
// hardcoded total that silently drifts if a profile's category count
// changes.
var expectedMdlMappingsFixed = []struct{ field, conversion string }{
	{"birth_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait", "base64StringToByteString"},
	{"portrait_capture_date", "stringToFullDate"},
	{"signature_usual_mark", "base64StringToByteString"},
}

func expectedMdlMappingsForProfile(categoryCount int) []struct{ field, conversion string } {
	out := append([]struct{ field, conversion string }{}, expectedMdlMappingsFixed...)
	for i := 0; i < categoryCount; i++ {
		out = append(out,
			struct{ field, conversion string }{"issue_date", "stringToFullDate"},
			struct{ field, conversion string }{"expiry_date", "stringToFullDate"},
		)
	}
	return out
}

// expectedPhotoIdMappings — isoPhotoId, unchanged by this task.
var expectedPhotoIdMappings = []struct{ field, conversion string }{
	{"birth_date", "stringToFullDate"},
	{"issue_date", "stringToFullDate"},
	{"expiry_date", "stringToFullDate"},
	{"portrait_capture_date", "stringToFullDate"},
}
```

- [ ] **Step 2: Reescribir `TestTrimmedProfileKeepsEveryConversionMapping`**

```go
// TestTrimmedProfileKeepsEveryConversionMapping is the guard that matters most
// around the credentialData trim. See expectedMdlMappingsForProfile for why a
// pairwise assertion beats a field count, and why it is computed per profile
// rather than hand-maintained as one flat total.
func TestTrimmedProfileKeepsEveryConversionMapping(t *testing.T) {
	raw := readProfilesConf(t)

	var want []string
	for n := 1; n <= 4; n++ {
		for _, m := range expectedMdlMappingsForProfile(n) {
			want = append(want, m.field+"="+m.conversion)
		}
	}
	for _, m := range expectedPhotoIdMappings {
		want = append(want, m.field+"="+m.conversion)
	}

	re := regexp.MustCompile(`"([a-z0-9_]+)"\s*=\s*\{[^{}]*?"conversionType"\s*=\s*"([A-Za-z0-9]+)"`)
	matches := re.FindAllStringSubmatch(raw, -1)
	got := make([]string, 0, len(matches))
	for _, m := range matches {
		got = append(got, m[1]+"="+m[2])
	}

	if len(got) != len(want) {
		t.Fatalf("profile carries %d conversion mappings, want %d\n got: %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("conversion mapping %d = %q, want %q — a trim that reaches into "+
				"entriesConfigMap changes the CBOR type of this field silently", i, got[i], want[i])
		}
	}

	if n := strings.Count(raw, "conversionType"); n != len(want) {
		t.Errorf("profile has %d conversionType occurrences, want %d", n, len(want))
	}
}
```

- [ ] **Step 3: Reescribir `TestCredentialDataCarriesOnlyTheKeptFields` para verificar los 4 bloques**

El actual usa `namespaceBlock` que solo encuentra la primera ocurrencia de
`"org.iso.18013.5.1" = {`. Cambiar a verificar las 4 ocurrencias (una por
perfil de mDL):

```go
// TestCredentialDataCarriesOnlyTheKeptFields pins the trim itself, across
// all 4 mDL profiles independently — each isoMdl_Ncat block repeats the
// same credentialData shape, and each is an equally real risk of an
// accidental trim, so each is checked on its own rather than trusting
// that checking one implies the other three are fine.
func TestCredentialDataCarriesOnlyTheKeptFields(t *testing.T) {
	raw := readProfilesConf(t)

	want := map[string]bool{}
	for _, f := range mdlKeepList {
		want[f] = true
	}

	blocks := allNamespaceBlocks(t, raw, `"org.iso.18013.5.1" = {`)
	if len(blocks) != 4 {
		t.Fatalf("found %d \"org.iso.18013.5.1\" credentialData blocks, want 4 (one per isoMdl_Ncat profile)", len(blocks))
	}

	for i, block := range blocks {
		got := fieldNamesIn(block)
		seen := map[string]bool{}
		for _, f := range got {
			seen[f] = true
			if !want[f] {
				t.Errorf("profile block %d: credentialData still declares %q — issuer-api2 deep-merges the "+
					"profile under our overrides, so this is emitted as a blank element in every mdoc we issue", i, f)
			}
		}
		for _, f := range mdlKeepList {
			if !seen[f] {
				t.Errorf("profile block %d: credentialData is missing %q — a field absent from the profile "+
					"cannot be populated by a runtime override", i, f)
			}
		}
	}
}

// allNamespaceBlocks returns the text between EVERY occurrence of `header`
// and its matching close brace — unlike namespaceBlock, which only finds
// the first. Needed once a HOCON file legitimately repeats the same
// namespace header across multiple profile blocks (isoMdl_1cat..isoMdl_4cat
// each declare their own "org.iso.18013.5.1" = { ... } credentialData).
func allNamespaceBlocks(t *testing.T, raw, header string) []string {
	t.Helper()
	var blocks []string
	rest := raw
	for {
		idx := strings.Index(rest, header)
		if idx < 0 {
			break
		}
		body := rest[idx+len(header):]
		depth := 1
		end := -1
		for i, r := range body {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatalf("unbalanced braces after %q", header)
		}
		blocks = append(blocks, body[:end])
		rest = body[end:]
	}
	if len(blocks) == 0 {
		t.Fatalf("namespace header %q not found — the profile shape changed", header)
	}
	return blocks
}
```

`namespaceBlock` (la función original de un solo bloque) se deja intacta
— sigue siendo válida como utilidad genérica, y no tiene otros llamadores
que dependan de que solo exista una ocurrencia.

- [ ] **Step 4: Correr la suite y confirmar el conteo real**

```bash
go test ./internal/adapters/waltid/... -run 'TestTrimmedProfileKeepsEveryConversionMapping|TestCredentialDataCarriesOnlyTheKeptFields' -v
```

Expected: ambos PASS. Si `TestTrimmedProfileKeepsEveryConversionMapping`
falla por un conteo distinto al esperado, comparar el número real
(`got`) contra el cálculo de la Task 1 Step 3
(`grep -c conversionType` = 4×6 fijas + 2×(1+2+3+4) de driving_privileges
+ 4 de Photo ID = 24+20+4 = 48) y corregir cualquier discrepancia en el
HOCON de la Task 1, no en el test.

- [ ] **Step 5: Commit**

```bash
git add internal/adapters/waltid/profiletrim_test.go
git commit -m "test(mdl): update profile trim guards for 4 mDL profiles"
```

---

### Task 7: Verificación end-to-end real contra el VPS

**Files:** ninguno (verificación manual, sin cambios de código)

**Interfaces:** ninguna nueva — consume todo lo construido en Tasks 1-6, desplegado.

- [ ] **Step 1: Ejecutar la suite Go completa localmente/en CI antes de desplegar**

```bash
cd verifiably-go
go build ./... && go vet ./...
go test ./internal/... ./vctypes/... -v 2>&1 | tail -100
```

Expected: build limpio, vet limpio, toda la suite en verde.

- [ ] **Step 2: Desplegar al VPS preservando el estado runtime existente**

Mismo patrón usado en toda esta sesión — respaldar los archivos runtime
(`issuer2-profiles.conf`, `credential-issuer-metadata.conf`,
`issuer-service.conf`, y los tres `*-service.conf` legacy) antes de
`git pull`, restaurarlos después, y ejecutar `./deploy.sh up waltid`.

```bash
ssh root@cdpi-vps '
cd /root/apps/demo-daas-3-0/verifiably-go
mkdir -p /root/pre-redeploy-save-drivingprivileges
cp deploy/k8s/config/issuer2/issuer2-profiles.conf /root/pre-redeploy-save-drivingprivileges/
cp deploy/k8s/config/issuer2/credential-issuer-metadata.conf /root/pre-redeploy-save-drivingprivileges/
cp deploy/k8s/config/issuer2/issuer-service.conf /root/pre-redeploy-save-drivingprivileges/
git checkout -- deploy/k8s/config/issuer2/issuer-service.conf deploy/k8s/config/issuer/issuer-service.conf deploy/k8s/config/verifier/verifier-service.conf
git pull origin feat/mdl
cp /root/pre-redeploy-save-drivingprivileges/issuer2-profiles.conf deploy/k8s/config/issuer2/issuer2-profiles.conf
cp /root/pre-redeploy-save-drivingprivileges/credential-issuer-metadata.conf deploy/k8s/config/issuer2/credential-issuer-metadata.conf
cp /root/pre-redeploy-save-drivingprivileges/issuer-service.conf deploy/k8s/config/issuer2/issuer-service.conf
'
```

**Importante:** el `issuer2-profiles.conf` runtime restaurado aquí sigue
teniendo el perfil `isoMdl` VIEJO (de 2 slots), no los 4 nuevos — porque es
un archivo gitignored que `git pull` no toca. Los 4 perfiles nuevos solo
llegan a producción vía `seed_issuer2_configs`'s `cp -n`, que **no
sobrescribe un runtime existente**. Este es exactamente el caso que
`docs/mdl-issuance-manual-checklist.md`'s migración baseline/runtime ya
documentó — para que el VPS adopte los 4 perfiles nuevos, el operador debe
fusionar manualmente el `issuer2-profiles.baseline.conf` nuevo con su
`issuer2-profiles.conf` runtime (que ya tiene el certificado/clave real
sustituidos), o borrar el runtime y dejar que `provision_issuer2_certificates`
lo re-siembre desde el baseline nuevo y re-sustituya el certificado real
(el "no-clobber" solo protege contra perder el certificado — no impide un
reseed limpio cuando el operador lo pide explícitamente).

Para esta verificación, dado que ya se decidió antes en esta sesión que
"no importa perder lo que está corriendo, es una prueba", la vía más
simple es:

```bash
ssh root@cdpi-vps '
cd /root/apps/demo-daas-3-0/verifiably-go
rm deploy/k8s/config/issuer2/issuer2-profiles.conf
./deploy.sh up waltid
'
```

`seed_issuer2_configs` re-siembra desde el `issuer2-profiles.baseline.conf`
nuevo (4 perfiles) y `provision_issuer2_certificates` detecta que
`dsc.pem`/`iaca.pem` ya existen (no los regenera — el certificado real
sigue siendo el mismo) y re-renderiza el `x5Chain`/`issuerKey` en los 4
perfiles nuevos porque el runtime recién sembrado todavía tiene el
certificado de ejemplo de walt.id (el no-clobber del render de x5chain se
basa en detectar ESE certificado específico, no en si el archivo es nuevo
o viejo).

- [ ] **Step 3: Verificar que los 4 perfiles cargaron con las referencias correctas**

```bash
ssh root@cdpi-vps '
docker run --rm --network waltid_default curlimages/curl:8.10.1 \
  -s "http://waltid-issuer-api2-1:7002/issuer2/profiles" > /tmp/profiles_check_final.json
python3 -c "
import json
d = json.load(open(\"/tmp/profiles_check_final.json\"))
print(\"profile IDs:\", list(d[0][\"credentialConfigs\"].keys()) if \"credentialConfigs\" in d[0] else \"unknown shape, inspect manually\")
"
'
```

Ajustar la ruta de lectura del JSON según la forma real que el endpoint
devuelva (confirmada en las sesiones previas de esta conversación —
revisar si es una lista con `credentialConfigs` o un mapa top-level de
`profiles`).

- [ ] **Step 4: Emitir 4 credenciales reales, una por cada conteo de categorías**

Repetir el mismo patrón de prueba usado en la investigación de esta
sesión (oferta → token → nonce → proof → credential vía
`POST /issuer2/credential-offers` con `profileId` explícito
`isoMdl_1cat`..`isoMdl_4cat`, y `driving_privileges` con 1/2/3/4 entradas
reales respectivamente), contra el `issuer-api2` de producción real
(`https://walt-issuer2.mtc.credenciales.ysalabs.work`), decodificando cada
CBOR resultante con `parseIssuerSigned` de `@animo-id/mdoc` (o `cbor2` en
Python) y confirmando:

- El array `driving_privileges` tiene exactamente 1, 2, 3, 4 entradas
  respectivamente — nunca duplicadas.
- El certificado en el `issuerAuth`'s `x5chain` es idéntico entre las 4
  credenciales (mismo certificado real, no el de ejemplo de walt.id en
  ninguna).
- La firma COSE_Sign1 verifica correctamente contra ese certificado en
  las 4 credenciales.

- [ ] **Step 5: Confirmar que Photo ID sigue funcionando sin cambios**

Emitir una credencial Photo ID real (perfil `isoPhotoId`, sin
`driving_privileges` en absoluto) y confirmar que redime exitosamente,
exactamente igual que antes de este cambio.

- [ ] **Step 6: Probar el formulario web real end-to-end**

Un humano (no un agente) debe:
1. Abrir el formulario de emisión mDL en el navegador.
2. Llenar solo 1 categoría de conducción, dejar el resto en blanco, y
   emitir.
3. Confirmar en la wallet que `driving_privileges` muestra exactamente 1
   fila, no 2.
4. Repetir con 2, 3, y 4 categorías llenadas.
5. Intentar emitir con 0 categorías (todas en blanco) y confirmar que el
   formulario devuelve el mensaje de error nuevo, sin llegar a crear la
   oferta.
6. Intentar llenar una 5ª categoría (si el formulario lo permite vía API
   directa, ya que el HTML solo renderiza 4 filas) y confirmar el mensaje
   de "máximo 4 categorías".

Esto no puede ser verificado por un agente — requiere una wallet real en
un dispositivo real, siguiendo el mismo estándar del resto de esta sesión
("boot ≠ exercise").

---

## Notas finales para quien ejecute este plan

- El orden de las tareas es deliberado: Task 1 (HOCON) antes de Task 3
  (Go que depende de los nombres de perfil) antes de Task 6 (tests que
  dependen de ambos). No reordenar.
- Cada `git commit` de este plan debe hacerse solo después de que la
  suite del paquete correspondiente esté en verde — no acumular cambios
  sin probar entre tareas.
- La Task 7 es la única que no se puede completar sin acceso al VPS real
  y (para el Step 6) a un dispositivo con la wallet instalada — si quien
  ejecuta este plan no tiene ese acceso, las Tasks 1-6 dejan el código
  listo pero **no verificado en producción**, y debe decirse
  explícitamente así al reportar el resultado.
