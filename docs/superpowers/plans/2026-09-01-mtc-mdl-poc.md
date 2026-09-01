# PoC mDL MTC — Fase 1 + Documento Guía — Plan de Implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Producir (a) un entorno Docker Compose aislado y reproducible en el que Inji
Certify emite un mDL (`mso_mdoc`, ISO/IEC 18013-5) conformante para la Licencia de Conducir,
con datos y firma mockeados, verificado por una herramienta standalone que no depende de
ninguna wallet; y (b) el documento guía en Markdown que el equipo del MTC/IUGO usa para
replicar esto contra su propio despliegue Inji Certify real.

**Architecture:** Todo el trabajo vive dentro de `verifiably-go` como documentación y
tooling de referencia — no se toca infraestructura del MTC ni código de producción de este
repo. El entorno reproducible extrae los servicios `inji-certify-preauth*` del
`docker-compose.yml` monolítico existente a un compose aislado nuevo, con un mock del
`MtcFeeDataProviderPlugin` (Java, plugin real de Inji Certify compilado contra su SPI) en
vez del data provider CSV que el compose original usa, y un SQL de seeding que aplica el
mismo patrón de `saveMdocSchema`/`mdocCredentialConfigValues` de
`internal/adapters/injicertify/db.go` — pero escrito a mano en SQL, porque el MTC no corre
`verifiably-go`. El verificador standalone generaliza `internal/mdl/testdata/verify/verify.mjs`
(que usa `@owf/mdoc`, una librería independiente de este repo) para aceptar cualquier CBOR y
certificado por argumento, en vez de los vectores fijos que usa hoy.

**Tech Stack:** Docker Compose, PostgreSQL 15, Inji Certify v0.14.0
(`injistack/inji-certify-with-plugins:0.14.0`), Java (mock data-provider plugin, siguiendo el
SPI real de Inji Certify), Node.js + `@owf/mdoc`/`@owf/cose` (verificador), Bash (orquestación
end-to-end), Markdown (documento guía).

**Spec:** `docs/superpowers/specs/2026-09-01-mtc-mdl-poc-design.md` — el plan implementa
únicamente la Fase 1 y el documento guía (Fase 2/3 son contenido a redactar dentro del
documento guía, no tareas de código — ver la sección "Alcance del plan de implementación"
del spec).

## Global Constraints

- **No se despliega código de este repo contra infraestructura real del MTC** — todo el
  entorno reproducible es local/aislado (spec, §Fuera de alcance).
- **No se modifica el flujo SD-JWT existente** — el `credential_config` mdoc es aditivo, un
  nuevo `credential_config_key_id`, nunca una modificación de los existentes A/B/E SD-JWT
  (spec, §Fuera de alcance).
- **Firma ECDSA P-256 exacta:** `key_manager_app_id = CERTIFY_VC_SIGN_EC_R1`,
  `key_manager_ref_id = EC_SECP256R1_SIGN`, `signature_crypto_suite = EcdsaSecp256r1Signature2019`
  — valores capturados verbatim del spike original, no aproximar (spec, hallazgo 6;
  `internal/adapters/injicertify/db.go:427`).
- **Template Velocity: tres condiciones simultáneas** — marcadores bracket-notation
  (`${rootContext['<namespace>'].<campo>}`), `driving_privileges` SIN comillas en el
  template, valor posteado como string JSON pre-serializado. Ninguna de las tres es
  opcional (spec, hallazgo 3).
- **Portrait queda roto y no se intenta arreglar** — limitación cerrada por desensamblado de
  bytecode (spec, hallazgo 4; commit `d222c33`). Documentar, no resolver.
- **El wrapper CBOR `{docType, issuerSigned}` no se corrige en esta Fase 1** — es un problema
  del lado de consumo (wallet), fuera del alcance de la emisión (spec, hallazgo 5, Fase 2).
- **Todo texto de cara al operador del MTC va en español**, siguiendo el tono ya establecido
  en los mensajes de error de `internal/adapters/injicertify/issuer.go` (p. ej.
  `"inji: driving_privileges es obligatorio en ISO 18013-5..."`).

---

## Decisión de modelado a tomar en la Tarea 1

El spec (§Fase 1, paso 2) deja abierta una decisión: ¿el `credential_config` mdoc del MTC
sigue el patrón "1 fila por clase A/B/E" que SD-JWT usa, o es una sola credencial con todas
las categorías que la persona realmente tiene? **Este plan adopta una sola credencial mdoc
con `driving_privileges` de longitud variable (1-4 categorías)** — no una fila por clase —
por las siguientes razones, registradas aquí porque el spec no las fija:

1. Es el modelo que ISO/IEC 18013-5 Table 3 realmente exige: `driving_privileges` es UN
   array dentro de UNA credencial, no una credencial por categoría.
2. Es el modelo que el spike original de este repo ya construyó y probó
   (`mdocCredentialConfigValues`, `DrivingPrivilegesMaxCategories` = 4) — reutilizarlo evita
   inventar un segundo patrón sin evidencia de que Inji Certify lo soporte.
3. El patrón "1 fila por clase" de SD-JWT existe porque SD-JWT modela cada clase como un
   `scope`/`credential_config` distinto — una restricción del formato SD-JWT del MTC, no un
   requisito de ISO 18013-5.

Esta decisión se documenta explícitamente en el documento guía (Tarea 6) como una discusión
abierta con el equipo del MTC, no como un hecho impuesto — el MTC puede preferir replicar el
patrón por clase por razones de negocio (p. ej. facturación por clase) que este plan no
conoce.

---

### Task 1: Seed SQL para la key policy EC y el `credential_config` mdoc

**Files:**
- Create: `docs/mtc-mdl-poc/compose/certify/init-mdoc.sql`
- Test: `docs/mtc-mdl-poc/compose/certify/init-mdoc_test.md` (checklist de verificación
  manual — no hay test automatizado de SQL puro en este repo; se verifica end-to-end en la
  Tarea 5)

**Interfaces:**
- Consumes: nada de tareas anteriores (primera tarea).
- Produces: dos artefactos SQL reusados por la Tarea 2 (compose) y la Tarea 5
  (script end-to-end):
  - Una fila `certify.key_policy_def` con `APP_ID = 'CERTIFY_VC_SIGN_EC_R1'`.
  - Una fila `certify.credential_config` con `credential_config_key_id = 'MTCDrivingLicenseMDL'`.

- [ ] **Step 1: Escribir el INSERT de `key_policy_def`**

Confirmado contra `deploy/compose/stack/inji/certify/init-preauth.sql:327` — reusar la
misma forma exacta (la tabla y sus columnas son parte del schema base de Inji Certify, no
algo que este repo inventó):

```sql
-- docs/mtc-mdl-poc/compose/certify/init-mdoc.sql
--
-- Seed SQL para que Inji Certify pueda firmar mso_mdoc con ECDSA P-256.
-- Aplica el mismo patrón que internal/adapters/injicertify/db.go's
-- saveMdocSchema, pero escrito a mano en SQL porque el MTC no corre
-- verifiably-go — ver docs/mtc-mdl-poc/README.md §Fase 1 para el contexto.
--
-- PRECONDICIÓN: correr esto SOLO si certify.key_policy_def no tiene ya una
-- fila CERTIFY_VC_SIGN_EC_R1. En un Inji Certify que solo ha emitido SD-JWT
-- (Ed25519), esta fila típicamente NO existe — confirmarlo primero con:
--   SELECT app_id FROM certify.key_policy_def WHERE app_id = 'CERTIFY_VC_SIGN_EC_R1';

INSERT INTO certify.key_policy_def(
    APP_ID, KEY_VALIDITY_DURATION, PRE_EXPIRE_DAYS, ACCESS_ALLOWED, IS_ACTIVE, CR_BY, CR_DTIMES
) VALUES (
    'CERTIFY_VC_SIGN_EC_R1', 1095, 60, 'NA', true, 'mtc-mdl-poc', now()
)
ON CONFLICT (APP_ID) DO NOTHING;
```

- [ ] **Step 2: Escribir el INSERT de `credential_config` mdoc**

Traduce a SQL directo lo que `saveMdocSchema` (`internal/adapters/injicertify/db.go:465-515`)
hace vía Go — mismas columnas, mismos valores de firma, mismo formato de `vc_template`
(la plantilla generada por `mdocVCTemplate`, con las tres condiciones del hallazgo 3
del spec ya aplicadas: bracket-notation, marcador sin comillas para `driving_privileges`,
namespace `org.iso.18013.5.1`). El campo `mandatory` mínimo de este PoC son los 11 elementos
ISO 18013-5 Table 3 más `driving_privileges` — se omiten los dos atributos de edad opcionales
(`age_over_18`/`age_over_21`) que `internal/mdl` sí incluye, porque no aparecen en los datos
que el FEE del MTC expone hoy (ver el "Riesgo de datos no verificado" del spec, §Fase 1
paso 4) — el documento guía (Tarea 6) señala esto como una decisión a revisar con datos
reales del FEE.

```sql
-- Continúa docs/mtc-mdl-poc/compose/certify/init-mdoc.sql

INSERT INTO certify.credential_config (
    credential_config_key_id, config_id, status, vc_template,
    doctype, sd_jwt_vct, context, credential_type, credential_format,
    did_url, key_manager_app_id, key_manager_ref_id,
    signature_algo, signature_crypto_suite, sd_claim,
    display, display_order, scope,
    cryptographic_binding_methods_supported,
    credential_signing_alg_values_supported,
    proof_types_supported,
    credential_subject, sd_jwt_claims, mso_mdoc_claims,
    plugin_configurations, cr_dtimes, upd_dtimes
) VALUES (
    'MTCDrivingLicenseMDL', 'MTCDrivingLicenseMDL', 'active',
    -- vc_template: base64 de un JSON con marcadores bracket-notation.
    -- Generado por scripts/render-mdoc-template.mjs (Tarea 1, Step 3) a
    -- partir de la lista de campos — NO se escribe el base64 a mano aquí
    -- porque un solo carácter mal puesto produce ERROR_SIGNING_QR_DATA en
    -- silencio (ver hallazgo 3 del spec). El placeholder de abajo se
    -- reemplaza por ese script antes de aplicar este SQL.
    '__VC_TEMPLATE_BASE64__',
    'org.iso.18013.5.1.mDL', NULL, NULL, NULL, 'mso_mdoc',
    NULL, 'CERTIFY_VC_SIGN_EC_R1', 'EC_SECP256R1_SIGN',
    'ES256', 'EcdsaSecp256r1Signature2019', NULL,
    '[{"name":"Licencia de Conducir MTC (mDL)","locale":"es","background_color":"#12107c","text_color":"#FFFFFF","logo":{"url":"https://mosip.github.io/inji-config/logos/agro-vertias-logo.png","alt_text":"MTC Logo"},"background_image":{"uri":"https://mosip.github.io/inji-config/logos/agro-vertias-logo.png"}}]'::JSONB,
    ARRAY['family_name','given_name','birth_date','issue_date','expiry_date',
          'issuing_country','issuing_authority','document_number','portrait',
          'driving_privileges','un_distinguishing_sign'],
    'mtc_driving_license_mdl',
    ARRAY['cose_key'],
    ARRAY['ES256'],
    '{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}'::JSONB,
    NULL, NULL,
    -- mso_mdoc_claims: mapa de campo -> display, anidado bajo el namespace
    -- ISO. Confirmado contra mdocCredentialConfigValues (db.go:415-422).
    '{"org.iso.18013.5.1":{
        "family_name":{"display":[{"name":"Apellidos","locale":"es"}]},
        "given_name":{"display":[{"name":"Nombres","locale":"es"}]},
        "birth_date":{"display":[{"name":"Fecha de nacimiento","locale":"es"}]},
        "issue_date":{"display":[{"name":"Fecha de emisión","locale":"es"}]},
        "expiry_date":{"display":[{"name":"Fecha de vencimiento","locale":"es"}]},
        "issuing_country":{"display":[{"name":"País emisor","locale":"es"}]},
        "issuing_authority":{"display":[{"name":"Autoridad emisora","locale":"es"}]},
        "document_number":{"display":[{"name":"Número de licencia","locale":"es"}]},
        "portrait":{"display":[{"name":"Fotografía","locale":"es"}]},
        "driving_privileges":{"display":[{"name":"Categorías de conducción","locale":"es"}]},
        "un_distinguishing_sign":{"display":[{"name":"Signo distintivo","locale":"es"}]}
    }}'::JSONB,
    NULL, NOW(), NULL
)
ON CONFLICT (credential_config_key_id) DO UPDATE SET
    vc_template            = EXCLUDED.vc_template,
    doctype                = EXCLUDED.doctype,
    credential_format      = EXCLUDED.credential_format,
    key_manager_app_id     = EXCLUDED.key_manager_app_id,
    key_manager_ref_id     = EXCLUDED.key_manager_ref_id,
    signature_algo         = EXCLUDED.signature_algo,
    signature_crypto_suite = EXCLUDED.signature_crypto_suite,
    display                = EXCLUDED.display,
    display_order          = EXCLUDED.display_order,
    mso_mdoc_claims         = EXCLUDED.mso_mdoc_claims,
    upd_dtimes             = NOW();
```

- [ ] **Step 3: Escribir el generador del `vc_template` (reemplaza el placeholder)**

`mdocVCTemplate` (`db.go:382-406`) es Go — este PoC no tiene un binario Go disponible en el
entorno del MTC, así que se porta a un script Node standalone que produce el mismo base64,
para poder generarlo también fuera de este repo:

```javascript
// docs/mtc-mdl-poc/compose/certify/render-mdoc-template.mjs
//
// Port de mdocVCTemplate (internal/adapters/injicertify/db.go:382-406) a
// Node standalone — el MTC no corre Go, así que este script es la forma
// portable de regenerar el vc_template si la lista de campos cambia.
// Produce EXACTAMENTE el mismo base64 que la función Go para la misma
// lista de campos — ver el test de la Tarea 1, Step 4.

const NAMESPACE = 'org.iso.18013.5.1';
const DRIVING_PRIVILEGES_FIELD = 'driving_privileges';

// Orden fijo: el digestID es el índice en este array, así que el orden
// importa para reproducibilidad pero no para corrección (Inji Certify no
// impone un orden específico de digestID).
const FIELDS = [
  'family_name', 'given_name', 'birth_date', 'issue_date', 'expiry_date',
  'issuing_country', 'issuing_authority', 'document_number', 'portrait',
  'driving_privileges', 'un_distinguishing_sign',
];

function renderTemplate(namespace, fields) {
  const itemLines = fields.map((name, digestID) => {
    const accessor = `rootContext['${namespace}'].${name}`;
    const elementValue = name === DRIVING_PRIVILEGES_FIELD
      ? `\${${accessor}}`
      : `"\${${accessor}}"`;
    return `      {"digestID": ${digestID}, "elementIdentifier": "${name}", "elementValue": ${elementValue}}`;
  });
  const out = '{\n' +
    '  "nameSpaces": {\n' +
    `    "${namespace}": [\n` +
    itemLines.join(',\n') + '\n' +
    '    ]\n' +
    '  },\n' +
    '  "docType": "${_doctype}",\n' +
    '  "validityInfo": {"validFrom": "${_validFrom}", "validUntil": "${_validUntil}"}\n' +
    '}';
  return Buffer.from(out, 'utf8').toString('base64');
}

const b64 = renderTemplate(NAMESPACE, FIELDS);
console.log(b64);
```

- [ ] **Step 4: Verificar que el template generado decodifica a JSON válido con las tres
  condiciones del hallazgo 3**

```bash
cd docs/mtc-mdl-poc/compose/certify
node render-mdoc-template.mjs > /tmp/template.b64
node -e "
  const b64 = require('fs').readFileSync('/tmp/template.b64', 'utf8').trim();
  const decoded = Buffer.from(b64, 'base64').toString('utf8');
  const parsed = JSON.parse(decoded); // debe parsear como JSON sin errores
  const dpItem = parsed.nameSpaces['org.iso.18013.5.1'].find(i => i.elementIdentifier === 'driving_privileges');
  if (typeof dpItem.elementValue !== 'string' || !dpItem.elementValue.startsWith('\${rootContext')) {
    throw new Error('driving_privileges debe ser un marcador SIN comillas — encontrado: ' + JSON.stringify(dpItem.elementValue));
  }
  const familyItem = parsed.nameSpaces['org.iso.18013.5.1'].find(i => i.elementIdentifier === 'family_name');
  if (familyItem.elementValue !== \"\\\${rootContext['org.iso.18013.5.1'].family_name}\") {
    throw new Error('family_name debe usar bracket-notation exacta — encontrado: ' + familyItem.elementValue);
  }
  console.log('OK: template cumple las tres condiciones del hallazgo 3');
"
```

Expected: `OK: template cumple las tres condiciones del hallazgo 3`

- [ ] **Step 5: Sustituir el placeholder en `init-mdoc.sql` por el base64 real**

```bash
cd docs/mtc-mdl-poc/compose/certify
TEMPLATE_B64=$(node render-mdoc-template.mjs)
sed -i "s|__VC_TEMPLATE_BASE64__|${TEMPLATE_B64}|" init-mdoc.sql
grep -q "VC_TEMPLATE_BASE64" init-mdoc.sql && echo "FALLO: el placeholder sigue presente" || echo "OK: placeholder reemplazado"
```

Expected: `OK: placeholder reemplazado`

- [ ] **Step 6: Commit**

```bash
git add docs/mtc-mdl-poc/compose/certify/init-mdoc.sql docs/mtc-mdl-poc/compose/certify/render-mdoc-template.mjs
git commit -m "docs(mtc-mdl-poc): seed SQL para key_policy_def EC y credential_config mdoc"
```

---

### Task 2: Mock del `MtcFeeDataProviderPlugin` (datos sintéticos)

**Files:**
- Create: `docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/` (proyecto Java mínimo)
- Create: `docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/src/main/java/pe/gob/mtc/mock/MockFeeDataProviderPlugin.java`
- Create: `docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/pom.xml`
- Test: `docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/src/test/java/pe/gob/mtc/mock/MockFeeDataProviderPluginTest.java`

**Interfaces:**
- Consumes: nada de tareas anteriores.
- Produces: un JAR (`mock-fee-plugin-1.0.0.jar`) que la Tarea 3 (compose) monta dentro del
  contenedor Inji Certify, implementando la misma interfaz SPI (`DataProviderPlugin`) que
  el `MtcFeeDataProviderPlugin` real del MTC — el contrato de esa interfaz (los métodos
  `fetchVcData`/similar) se toma de la documentación pública de Inji Certify sobre plugins
  DataProvider (`docs.inji.io` — Certify components, citado en el resumen técnico del MTC),
  no de código propietario del MTC que este repo no tiene.

**Nota de alcance:** este mock existe únicamente para que el entorno reproducible pueda
emitir mdocs de prueba sin depender del Servicio Web FEE real del MTC — no reemplaza ni
simula la lógica de negocio real del FEE (autenticación `ExternalToken`,
`ObtenerInformacionLicenciaPersona`). Devuelve datos sintéticos fijos.

- [ ] **Step 1: Escribir el mock plugin con datos sintéticos, incluyendo `driving_privileges`
  con 1 y con 4 categorías según un parámetro de entrada**

```java
// docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/src/main/java/pe/gob/mtc/mock/MockFeeDataProviderPlugin.java
//
// Mock del MtcFeeDataProviderPlugin real del MTC — SOLO para el entorno de
// pruebas reproducible de esta PoC. No reemplaza la integración real con el
// Servicio Web FEE (ExternalToken / ObtenerInformacionLicenciaPersona).
//
// Devuelve driving_privileges con la forma EXACTA que ISO/IEC 18013-5
// Table 3 exige — un array de objetos con vehicle_category_code/issue_date/
// expiry_date por categoría. Esto es una SUPOSICIÓN sobre la forma real que
// el FEE devuelve (ver spec §Fase 1 paso 4, "Riesgo de datos no
// verificado") — el documento guía (Tarea 6) marca esto explícitamente
// como algo a confirmar contra el FEE real antes de escribir el plugin
// real de producción.
package pe.gob.mtc.mock;

import java.util.*;

public class MockFeeDataProviderPlugin {

    /**
     * Categorías sintéticas por número de documento de prueba.
     * "MOCK-1CAT" -> 1 categoría, "MOCK-4CAT" -> 4 categorías — para que el
     * script end-to-end (Tarea 5) pueda emitir ambos casos sin cambiar el
     * plugin.
     */
    public List<Map<String, Object>> drivingPrivilegesFor(String documentNumber) {
        int count = documentNumber.endsWith("4CAT") ? 4 : 1;
        String[] categories = {"A-I", "A-IIa", "A-IIb", "B-IIc"};
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Map<String, Object> priv = new LinkedHashMap<>();
            priv.put("vehicle_category_code", categories[i]);
            priv.put("issue_date", "2020-01-15");
            priv.put("expiry_date", "2030-01-15");
            out.add(priv);
        }
        return out;
    }

    public Map<String, Object> credentialSubjectFor(String documentNumber) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("family_name", "PRUEBA");
        subject.put("given_name", "OPERADOR MTC");
        subject.put("birth_date", "1990-05-20");
        subject.put("issue_date", "2024-01-01");
        subject.put("expiry_date", "2029-01-01");
        subject.put("issuing_country", "PE");
        subject.put("issuing_authority", "MTC");
        subject.put("document_number", documentNumber);
        subject.put("un_distinguishing_sign", "PE");
        // portrait deliberadamente omitido de este mock: el hallazgo 4 del
        // spec ya confirmó (por desensamblado de bytecode) que Inji Certify
        // no lo codifica correctamente sin importar el valor — no tiene
        // sentido cablear un JPEG de prueba en un mock cuyo propósito es
        // probar el resto del flujo.
        return subject;
    }
}
```

- [ ] **Step 2: Escribir el test del mock**

```java
// docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/src/test/java/pe/gob/mtc/mock/MockFeeDataProviderPluginTest.java
package pe.gob.mtc.mock;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class MockFeeDataProviderPluginTest {

    @Test
    void oneCategoryDocumentReturnsOnePrivilege() {
        var plugin = new MockFeeDataProviderPlugin();
        List<Map<String, Object>> privileges = plugin.drivingPrivilegesFor("MOCK-1CAT");
        assertEquals(1, privileges.size());
        assertEquals("A-I", privileges.get(0).get("vehicle_category_code"));
        assertNotNull(privileges.get(0).get("issue_date"));
        assertNotNull(privileges.get(0).get("expiry_date"));
    }

    @Test
    void fourCategoryDocumentReturnsFourPrivileges() {
        var plugin = new MockFeeDataProviderPlugin();
        List<Map<String, Object>> privileges = plugin.drivingPrivilegesFor("MOCK-4CAT");
        assertEquals(4, privileges.size());
    }

    @Test
    void credentialSubjectHasNoPortrait() {
        var plugin = new MockFeeDataProviderPlugin();
        Map<String, Object> subject = plugin.credentialSubjectFor("MOCK-1CAT");
        assertFalse(subject.containsKey("portrait"),
            "portrait se omite deliberadamente — ver el comentario del hallazgo 4 en la clase");
    }
}
```

- [ ] **Step 3: Run test to verify it fails (antes de escribir `pom.xml`, no compila)**

Run: `cd docs/mtc-mdl-poc/compose/certify/mock-fee-plugin && mvn test`
Expected: FAIL — `pom.xml` no existe todavía.

- [ ] **Step 4: Escribir `pom.xml` mínimo (Java 17, JUnit 5)**

```xml
<!-- docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/pom.xml -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>pe.gob.mtc.mock</groupId>
  <artifactId>mock-fee-plugin</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>3.2.5</version>
      </plugin>
    </plugins>
  </build>
</project>
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd docs/mtc-mdl-poc/compose/certify/mock-fee-plugin && mvn test`
Expected: `Tests run: 3, Failures: 0, Errors: 0`

- [ ] **Step 6: Empaquetar el JAR**

Run: `cd docs/mtc-mdl-poc/compose/certify/mock-fee-plugin && mvn package`
Expected: `BUILD SUCCESS`, produce `target/mock-fee-plugin-1.0.0.jar`

- [ ] **Step 7: Commit**

```bash
git add docs/mtc-mdl-poc/compose/certify/mock-fee-plugin/
git commit -m "docs(mtc-mdl-poc): mock del MtcFeeDataProviderPlugin con datos sintéticos"
```

---

### Task 3: Extraer el compose aislado de Inji Certify Pre-Auth

**Files:**
- Create: `docs/mtc-mdl-poc/compose/docker-compose.yml`
- Create: `docs/mtc-mdl-poc/compose/certify-nginx/nginx.conf`
- Create: `docs/mtc-mdl-poc/compose/certify-nginx/certs/` (certificado de prueba autofirmado,
  generado en el Step 2, no versionado — ver `.gitignore`)
- Modify: crear `docs/mtc-mdl-poc/.gitignore`

**Interfaces:**
- Consumes: `init-mdoc.sql` (Tarea 1), `mock-fee-plugin-1.0.0.jar` (Tarea 2).
- Produces: un servicio Inji Certify accesible en `http://localhost:8094` una vez levantado
  — consumido por la Tarea 5 (script end-to-end).

**Nota (spec, corrección de ruta B-1):** no existe un compose Pre-Auth aislado en este repo
hoy — esta tarea extrae los servicios equivalentes del monolito
`deploy/compose/stack/docker-compose.yml` (líneas ~517-710, confirmadas en la investigación
del plan: `certify-preauth-postgres`, `inji-certify-preauth-backend`, `certify-preauth-nginx`)
a un compose nuevo y autocontenido, quitando toda dependencia de Caddy, del proxy
`inji-preauth-proxy` (innecesario aquí — este entorno no necesita servir metadata OID4VCI a
una wallet estricta como walt.id, solo emitir y verificar con el script de la Tarea 5 que
habla HTTP directo) y de los demás servicios del stack completo (Mimoto, Inji Verify, etc.
— fuera de alcance de la Fase 1).

- [ ] **Step 1: Escribir el `docker-compose.yml` aislado**

```yaml
# docs/mtc-mdl-poc/compose/docker-compose.yml
#
# Entorno aislado y reproducible para la Fase 1 de la PoC mDL del MTC.
# Extraído de verifiably-go/deploy/compose/stack/docker-compose.yml
# (servicios inji-certify-preauth*), sin Caddy ni el proxy
# inji-preauth-proxy — este entorno solo necesita responder HTTP directo al
# script end-to-end de la Tarea 5, no servir a una wallet estricta.
#
# NO cubre: CloudHSM real, certificado de la CA MTC/RENIEC, IACA/trust
# anchors reales — ver docs/mtc-mdl-poc/README.md §Riesgos.

services:
  certify-postgres:
    image: postgres:15
    restart: unless-stopped
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: inji_certify
    volumes:
      - ./certify/init-preauth.sql:/docker-entrypoint-initdb.d/01-init.sql:ro
      - ./certify/init-mdoc.sql:/docker-entrypoint-initdb.d/02-init-mdoc.sql:ro
      - certify-db:/var/lib/postgresql/data
    ports:
      - "127.0.0.1:5436:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5
      start_period: 90s

  certify:
    image: injistack/inji-certify-with-plugins:0.14.0
    restart: unless-stopped
    user: root
    environment:
      - container_user=mosip
      - active_profile_env=default,mtc-mock-fee
      - SPRING_CONFIG_NAME=certify
      - SPRING_CONFIG_LOCATION=/home/mosip/config/
      - enable_certify_artifactory=false
      - download_hsm_client=false
      - CERTIFY_ISSUER_DID=did:web:certify-nginx
      - ISSUER_DISPLAY_NAME=MTC PoC mDL (entorno de pruebas)
      - mosip_certify_domain_url=http://localhost:8094
      - MOSIP_CERTIFY_AUTHN_JWK_SET_URI=http://certify:8090/v1/certify/.well-known/jwks.json
      - SPRING_DATASOURCE_URL=jdbc:postgresql://certify-postgres:5432/inji_certify
      - SPRING_DATASOURCE_USERNAME=postgres
      - SPRING_DATASOURCE_PASSWORD=postgres
    volumes:
      - ./certify/certify-default.properties:/home/mosip/config/certify-default.properties:ro
      - ./certify/certify-mtc-mock-fee.properties:/home/mosip/config/certify-mtc-mock-fee.properties:ro
      - ./certify/mock-fee-plugin/target/mock-fee-plugin-1.0.0.jar:/home/mosip/additional_jars/mock-fee-plugin-1.0.0.jar:ro
      - certify-pkcs12:/home/inji/CERTIFY_PKCS12
    depends_on:
      certify-postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://localhost:8090/v1/certify/actuator/health || exit 1"]
      interval: 15s
      timeout: 10s
      start_period: 120s
      retries: 10

  certify-nginx:
    image: nginx:1.27
    restart: unless-stopped
    ports:
      - "127.0.0.1:8094:80"
    volumes:
      - ./certify-nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certify-nginx/certs/nginx.crt:/etc/nginx/certs/nginx.crt:ro
      - ./certify-nginx/certs/nginx.key:/etc/nginx/certs/nginx.key:ro
    depends_on:
      - certify

volumes:
  certify-db:
  certify-pkcs12:
```

- [ ] **Step 2: Generar el certificado de prueba autofirmado para nginx**

```bash
mkdir -p docs/mtc-mdl-poc/compose/certify-nginx/certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout docs/mtc-mdl-poc/compose/certify-nginx/certs/nginx.key \
  -out docs/mtc-mdl-poc/compose/certify-nginx/certs/nginx.crt \
  -days 365 -subj "/CN=certify-nginx (MTC mDL PoC — NO USAR EN PRODUCCIÓN)"
```

- [ ] **Step 3: Escribir `nginx.conf` (proxy simple hacia el contenedor `certify`)**

```nginx
# docs/mtc-mdl-poc/compose/certify-nginx/nginx.conf
server {
    listen 80;
    server_name certify-nginx;

    location / {
        proxy_pass http://certify:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

- [ ] **Step 4: Copiar `certify-default.properties` del stack existente sin modificar**

```bash
cp verifiably-go/deploy/compose/stack/inji/certify/certify-default.properties \
   docs/mtc-mdl-poc/compose/certify/certify-default.properties
```

Confirmado en la investigación de este plan que este archivo ya trae el mapeo
`'ES256': {{'CERTIFY_VC_SIGN_EC_R1', 'EC_SECP256R1_SIGN'}}` (línea 214) — no necesita
edición para soportar mdoc, solo la fila de `key_policy_def` (Tarea 1) para que la política
exista en la base de datos.

- [ ] **Step 5: Escribir `certify-mtc-mock-fee.properties` (activa el mock plugin en vez del
  data provider CSV real)**

```properties
# docs/mtc-mdl-poc/compose/certify/certify-mtc-mock-fee.properties
#
# Activa pe.gob.mtc.mock.MockFeeDataProviderPlugin (Tarea 2) como el
# DataProvider plugin de este entorno de pruebas — NO es la configuración
# real del MTC (certify-driver-license.properties, con MtcFeeDataProviderPlugin
# real contra el Servicio Web FEE).
mosip.certify.integration.data-provider-plugin=MockFeeDataProviderPlugin
mosip.certify.integration.scan-base-package=pe.gob.mtc.mock
```

- [ ] **Step 6: Escribir `.gitignore` (nunca versionar el certificado/clave de prueba)**

```
# docs/mtc-mdl-poc/.gitignore
compose/certify-nginx/certs/*.crt
compose/certify-nginx/certs/*.key
```

- [ ] **Step 7: Levantar el entorno y confirmar healthcheck verde**

```bash
cd docs/mtc-mdl-poc/compose
docker compose up -d
docker compose ps
```

Expected: los tres servicios (`certify-postgres`, `certify`, `certify-nginx`) en estado
`healthy`/`running` dentro de 2 minutos (`certify` tiene `start_period: 120s`).

- [ ] **Step 8: Commit**

```bash
git add docs/mtc-mdl-poc/.gitignore docs/mtc-mdl-poc/compose/docker-compose.yml \
        docs/mtc-mdl-poc/compose/certify-nginx/nginx.conf \
        docs/mtc-mdl-poc/compose/certify/certify-default.properties \
        docs/mtc-mdl-poc/compose/certify/certify-mtc-mock-fee.properties
git commit -m "docs(mtc-mdl-poc): entorno docker-compose aislado para Inji Certify mdoc"
```

---

### Task 4: Verificador standalone generalizado (basado en `verify.mjs`)

**Files:**
- Create: `docs/mtc-mdl-poc/verify/verify-mdoc.mjs`
- Create: `docs/mtc-mdl-poc/verify/package.json`
- Test: `docs/mtc-mdl-poc/verify/verify-mdoc.test.mjs`

**Interfaces:**
- Consumes: nada de tareas anteriores directamente (es una herramienta independiente); se
  usa contra la salida de la Tarea 5.
- Produces: un script CLI `node verify-mdoc.mjs <cbor-file> <iaca-pem> [--expected-elements=N]
  [--doctype=X] [--namespace=Y]` que la Tarea 5 invoca, con exit code 0/1.

**Nota (spec, B-3):** `internal/mdl/testdata/verify/verify.mjs` no es reusable tal cual — usa
constantes hardcodeadas (`EXPECTED_ELEMENTS = 13`, `EXPIRY_DATE`, rutas de archivo fijas) y
dos checks específicos de sus propios vectores versionados ("DSC marcado POC",
"60 días de validez restante"). Esta tarea generaliza la lógica de verificación real
(`ctx` de `MdocContext`, los checks de integridad criptográfica) y parametriza todo lo
demás vía argumentos CLI.

- [ ] **Step 1: Escribir el test del verificador generalizado, contra un CBOR de prueba real**

Reusa como fixture uno de los vectores ya versionados en `internal/mdl/testdata/vectors/`
(no se genera un fixture nuevo — ya existe uno conformante en este repo):

```javascript
// docs/mtc-mdl-poc/verify/verify-mdoc.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// Fixture reusado de internal/mdl — un mdoc conformante ya generado y
// versionado por este repo, independiente de esta PoC.
const vectors = join(here, '..', '..', '..', 'verifiably-go', 'internal', 'mdl', 'testdata', 'vectors');

test('un mdoc conformante pasa la verificación con exit code 0', () => {
  const result = execFileSync('node', [
    join(here, 'verify-mdoc.mjs'),
    join(vectors, 'mdl_full.cbor'),
    join(vectors, 'iaca.pem'),
    '--expected-elements=13',
  ], { encoding: 'utf8' });
  assert.match(result, /All checks passed/);
});

test('un CBOR corrupto falla con exit code distinto de 0', () => {
  assert.throws(() => {
    execFileSync('node', [
      join(here, 'verify-mdoc.mjs'),
      join(here, 'verify-mdoc.test.mjs'), // no es un CBOR válido, a propósito
      join(vectors, 'iaca.pem'),
    ], { encoding: 'utf8' });
  });
});

test('acepta un número distinto de elementos esperados sin fallar el parseo', () => {
  // driving_privileges de 1 categoría vs 4 categorías no cambia
  // EXPECTED_ELEMENTS (los elementos son 11 fijos de Table 3 + el array
  // driving_privileges como UN elemento, sin importar cuántas entradas
  // tenga el array) — este test documenta esa distinción para quien
  // reutilice el script.
  const result = execFileSync('node', [
    join(here, 'verify-mdoc.mjs'),
    join(vectors, 'mdl_full.cbor'),
    join(vectors, 'iaca.pem'),
    '--expected-elements=13',
    '--doctype=org.iso.18013.5.1.mDL',
    '--namespace=org.iso.18013.5.1',
  ], { encoding: 'utf8' });
  assert.match(result, /All checks passed/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd docs/mtc-mdl-poc/verify && node --test verify-mdoc.test.mjs`
Expected: FAIL — `verify-mdoc.mjs` no existe todavía.

- [ ] **Step 3: Escribir `verify-mdoc.mjs` — generalización de `verify.mjs`**

Reusa `ctx` (el `MdocContext` completo: `crypto`, `cose.sign1.verify`, `x509.*`) tal cual de
`internal/mdl/testdata/verify/verify.mjs:66-221` sin cambios (es la parte que hace el
trabajo criptográfico real, no depende de ningún vector fijo). Cambia: argumentos CLI en vez
de constantes, quita los checks 6-7 (DSC-days-left, "marked POC") que son específicos de los
vectores versionados de `internal/mdl`, y permite un solo certificado (`iaca.pem`) en vez de
asumir también `dsc.pem` por separado (el `x5chain` de la credencial ya trae el DSC).

```javascript
#!/usr/bin/env node
// docs/mtc-mdl-poc/verify/verify-mdoc.mjs
//
// Verificador standalone de mdocs — generalización de
// internal/mdl/testdata/verify/verify.mjs (mismo repo, mismo enfoque:
// @owf/mdoc es una implementación independiente de este proyecto, así que
// una lectura equivocada del estándar de nuestro lado no pasaría aquí
// también). A diferencia del original, acepta CUALQUIER mdoc y certificado
// por argumento — no está cableado a los vectores de internal/mdl.
//
// Uso:
//   node verify-mdoc.mjs <archivo.cbor> <iaca.pem> \
//     [--expected-elements=N] [--doctype=X] [--namespace=Y]

import { readFileSync } from 'node:fs';
import { X509Certificate, createHash, randomBytes, webcrypto } from 'node:crypto';
import { parseArgs } from 'node:util';

import { IssuerSigned, MdlError } from '@owf/mdoc';
import { CoseKey, SignatureAlgorithm } from '@owf/cose';

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    'expected-elements': { type: 'string' },
    doctype: { type: 'string', default: 'org.iso.18013.5.1.mDL' },
    namespace: { type: 'string', default: 'org.iso.18013.5.1' },
  },
});

if (positionals.length < 2) {
  console.error('Uso: node verify-mdoc.mjs <archivo.cbor> <iaca.pem> [--expected-elements=N] [--doctype=X] [--namespace=Y]');
  process.exit(2);
}

const [cborPath, iacaPath] = positionals;
const EXPECTED_ELEMENTS = values['expected-elements'] ? parseInt(values['expected-elements'], 10) : null;
const DOCTYPE = values.doctype;
const NAMESPACE = values.namespace;
const NOW = new Date();

const mdocBytes = new Uint8Array(readFileSync(cborPath));
const iacaCert = new X509Certificate(readFileSync(iacaPath, 'utf8'));

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
};

const derOf = (cert) => new Uint8Array(cert.raw);

const subtleAlgFor = (alg) => {
  switch (alg) {
    case SignatureAlgorithm.ES256: return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
    case SignatureAlgorithm.ES384: return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' };
    case SignatureAlgorithm.ES512: return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' };
    default: throw new Error(`verify-mdoc: algoritmo COSE no soportado ${alg}`);
  }
};

// MdocContext — idéntico a internal/mdl/testdata/verify/verify.mjs (esta es
// la parte independiente de nuestro propio código que hace el trabajo
// criptográfico real; no depende de qué CBOR/certificado se le pase).
const ctx = {
  fetch,
  crypto: {
    random: (length) => new Uint8Array(randomBytes(length)),
    digest: ({ digestAlgorithm, bytes }) =>
      new Uint8Array(createHash(digestAlgorithm.replace('-', '')).update(bytes).digest()),
    hdkf: () => { throw new Error('verify-mdoc: HKDF no implementado; no requerido para verificación de emisión'); },
  },
  cose: {
    sign1: {
      sign: () => { throw new Error('verify-mdoc: firma no implementada; este script solo verifica'); },
      verify: async ({ toBeVerified, signature, key, algorithm }) => {
        const alg = algorithm ?? key.algorithm ?? SignatureAlgorithm.ES256;
        const params = subtleAlgFor(alg);
        const imported = await webcrypto.subtle.importKey(
          'jwk', key.jwk, { name: params.name, namedCurve: params.namedCurve }, false, ['verify'],
        );
        return webcrypto.subtle.verify({ name: params.name, hash: params.hash }, imported, signature, toBeVerified);
      },
    },
    mac0: {
      generate: () => { throw new Error('verify-mdoc: MAC0 no implementado'); },
      verify: () => { throw new Error('verify-mdoc: MAC0 no implementado'); },
    },
  },
  x509: {
    getIssuerNameField: ({ certificate, field }) => {
      const cert = new X509Certificate(Buffer.from(certificate));
      return cert.issuer.split('\n').map((line) => line.split('=')).filter(([k]) => k.trim() === field).map(([, v]) => v.trim());
    },
    getPublicKey: async ({ certificate, algorithm }) => {
      const cert = new X509Certificate(Buffer.from(certificate));
      const jwk = cert.publicKey.export({ format: 'jwk' });
      const key = CoseKey.fromJwk(jwk);
      if (algorithm !== undefined && key.algorithm === undefined) {
        return CoseKey.create({ keyType: key.keyType, curve: key.curve, x: key.x, y: key.y, algorithm });
      }
      return key;
    },
    verifyCertificateChain: ({ trustedCertificates, x5chain, now = NOW }) => {
      if (!x5chain || x5chain.length === 0) throw new Error('verify-mdoc: x5chain vacío');
      const chain = x5chain.map((der) => new X509Certificate(Buffer.from(der)));
      const anchors = trustedCertificates.map((der) => new X509Certificate(Buffer.from(der)));
      for (const cert of chain) {
        if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
          throw new Error(`verify-mdoc: certificado ${cert.subject} no es válido en ${now.toISOString()}`);
        }
      }
      for (let i = 0; i < chain.length - 1; i += 1) {
        if (!chain[i].verify(chain[i + 1].publicKey)) {
          throw new Error(`verify-mdoc: ${chain[i].subject} no está firmado por ${chain[i + 1].subject}`);
        }
      }
      const top = chain[chain.length - 1];
      const anchor = anchors.find((a) => {
        if (a.raw.equals(top.raw)) return a.ca;
        return top.verify(a.publicKey) && a.ca;
      });
      if (!anchor) throw new Error('verify-mdoc: la cadena no termina en un certificado CA de confianza');
      if (now < new Date(anchor.validFrom) || now > new Date(anchor.validTo)) {
        throw new Error('verify-mdoc: el ancla de confianza no es válida al momento de verificar');
      }
      const out = chain.map((c) => new Uint8Array(c.raw));
      if (!anchor.raw.equals(top.raw)) out.push(new Uint8Array(anchor.raw));
      return { chain: out };
    },
    getCertificateData: ({ certificate }) => {
      const cert = new X509Certificate(Buffer.from(certificate));
      return {
        issuerName: cert.issuer, subjectName: cert.subject, serialNumber: cert.serialNumber,
        thumbprint: cert.fingerprint256, notBefore: new Date(cert.validFrom), notAfter: new Date(cert.validTo),
        pem: cert.toString(),
      };
    },
  },
};

let issuerSigned;
try {
  issuerSigned = IssuerSigned.decode(mdocBytes);
  check('IssuerSigned decodifica bajo los esquemas de @owf/mdoc', true);
} catch (err) {
  check('IssuerSigned decodifica bajo los esquemas de @owf/mdoc', false, err.message);
  console.log('\nNo se puede continuar sin un IssuerSigned parseado.');
  process.exit(1);
}

const mso = issuerSigned.issuerAuth.mobileSecurityObject;
const assessments = [];
try {
  const result = await issuerSigned.verify(
    { now: NOW, trustedCertificates: [{ issuance: [derOf(iacaCert)] }], disableStatusValidation: true, verificationCallback: (a) => assessments.push(a) },
    ctx,
  );
  const failed = assessments.filter((a) => a.status === 'FAILED');
  for (const a of failed) console.log(`      assessment fallido [${a.category}] ${a.check}${a.reason ? `: ${a.reason}` : ''}`);
  check('verificación completa del emisor (firma, cadena, digests)', failed.length === 0, `${assessments.length} assessments, ${failed.length} fallidos`);
  check('la cadena termina en el ancla de confianza (IACA)', !!result.trustedIssuanceChain && result.trustedIssuanceChain.length >= 2,
    result.trustedIssuanceChain ? `${result.trustedIssuanceChain.length} certificados` : 'sin cadena de confianza');
} catch (err) {
  check('verificación completa del emisor (firma, cadena, digests)', false, err instanceof MdlError ? err.message : String(err));
  check('la cadena termina en el ancla de confianza (IACA)', false, 'la verificación lanzó una excepción');
}

check('docType coincide con el esperado', mso.docType === DOCTYPE, `${mso.docType} (esperado: ${DOCTYPE})`);

const digestIds = mso.valueDigests.getDigestIdsForNamespace(NAMESPACE);
check('valueDigests presentes para el namespace ISO', mso.valueDigests.getNamespaces().includes(NAMESPACE), mso.valueDigests.getNamespaces().join(', '));
if (EXPECTED_ELEMENTS !== null) {
  check(`${EXPECTED_ELEMENTS} elementos comprometidos (digests)`, digestIds.length === EXPECTED_ELEMENTS, String(digestIds.length));
} else {
  console.log(`INFO  ${digestIds.length} elementos comprometidos (digests) — sin valor esperado dado, no se compara`);
}

const items = issuerSigned.getIssuerNamespace(NAMESPACE) ?? [];
if (EXPECTED_ELEMENTS !== null) {
  check(`${EXPECTED_ELEMENTS} elementos divulgables en el namespace ISO`, items.length === EXPECTED_ELEMENTS, String(items.length));
} else {
  console.log(`INFO  ${items.length} elementos divulgables en el namespace ISO`);
}

const drivingPrivilegesItem = items.find((i) => i.elementIdentifier === 'driving_privileges');
if (drivingPrivilegesItem) {
  const value = drivingPrivilegesItem.elementValue;
  check('driving_privileges es un array real (no un string)', Array.isArray(value), typeof value);
  if (Array.isArray(value)) {
    check('driving_privileges tiene al menos 1 categoría', value.length >= 1, `${value.length} categorías`);
    check('cada categoría tiene vehicle_category_code', value.every((p) => typeof p.vehicle_category_code === 'string' && p.vehicle_category_code.length > 0));
  }
} else {
  console.log('INFO  driving_privileges no está presente en este mdoc (Photo ID u otro docType sin ese elemento)');
}

const validity = mso.validityInfo;
check('validityInfo presente', !!validity);
check('validFrom precede a validUntil', !!validity && validity.validFrom < validity.validUntil);

check('el MSO vincula una device key', !!mso.deviceKeyInfo?.deviceKey, mso.deviceKeyInfo?.deviceKey ? `curva ${mso.deviceKeyInfo.deviceKey.curve}` : 'ausente');

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
```

- [ ] **Step 4: Escribir `package.json`**

```json
{
  "name": "mtc-mdl-poc-verify",
  "private": true,
  "type": "module",
  "description": "Verificador standalone de mdocs para la PoC mDL del MTC — generalización de internal/mdl/testdata/verify/verify.mjs.",
  "dependencies": {
    "@owf/cose": "^0.3.0",
    "@owf/mdoc": "^0.7.0"
  }
}
```

- [ ] **Step 5: Instalar dependencias y correr el test**

```bash
cd docs/mtc-mdl-poc/verify
npm install
node --test verify-mdoc.test.mjs
```

Expected: `# pass 3` (los tres tests de Step 1 pasan)

- [ ] **Step 6: Commit**

```bash
git add docs/mtc-mdl-poc/verify/
git commit -m "docs(mtc-mdl-poc): verificador standalone de mdocs (generaliza verify.mjs)"
```

---

### Task 5: Script end-to-end — emitir y verificar 1 y 4 categorías

**Files:**
- Create: `docs/mtc-mdl-poc/compose/scripts/run-e2e.sh`
- Test: el propio script ES el test — se corre y se observa su exit code (patrón de este
  repo para scripts de verificación end-to-end, ver `tests/test_seed_issuer2_configs.sh`
  citado en la memoria del proyecto).

**Interfaces:**
- Consumes: el entorno levantado por la Tarea 3 (`http://localhost:8094`), el verificador de
  la Tarea 4 (`docs/mtc-mdl-poc/verify/verify-mdoc.mjs`).
- Produces: el criterio de cierre de la Fase 1 completo — este script, al pasar, es la
  prueba de que "Fase 1: hecho" (spec, §Criterios de aceptación).

- [ ] **Step 1: Escribir el script — emite vía `pre-authorized-data`, extrae el CBOR, corre
  el verificador, para 1 y 4 categorías**

```bash
#!/usr/bin/env bash
# docs/mtc-mdl-poc/compose/scripts/run-e2e.sh
#
# Criterio de cierre de la Fase 1 (spec §Criterios de aceptación): emite un
# mDL con 1 categoría y otro con 4, vía el flujo OID4VCI pre-authorized_code
# real contra el entorno de la Tarea 3, y confirma que ambos pasan la
# verificación standalone de la Tarea 4.
set -euo pipefail

CERTIFY_URL="http://localhost:8094"
VERIFY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../verify" && pwd)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

issue_and_verify() {
  local document_number="$1"
  local label="$2"

  echo "=== Emitiendo mDL para $document_number ($label) ==="

  # 1. Solicitar la oferta pre-authorized_code.
  local offer_response
  offer_response=$(curl -sf -X POST "$CERTIFY_URL/v1/certify/pre-authorized-data" \
    -H "Content-Type: application/json" \
    -d "{
      \"credential_configuration_id\": \"MTCDrivingLicenseMDL\",
      \"claims\": {\"document_number\": \"$document_number\"}
    }")

  local pre_auth_code
  pre_auth_code=$(echo "$offer_response" | node -e "
    const data = JSON.parse(require('fs').readFileSync(0, 'utf8'));
    const uri = data.credential_offer_uri || data.credential_offer;
    const offer = typeof uri === 'string' && uri.startsWith('openid-credential-offer://')
      ? JSON.parse(decodeURIComponent(uri.split('credential_offer=')[1]))
      : data;
    console.log(offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']);
  ")

  # 2. Canjear el código por un access token.
  local token_response
  token_response=$(curl -sf -X POST "$CERTIFY_URL/v1/certify/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
    --data-urlencode "pre-authorized_code=$pre_auth_code")

  local access_token c_nonce
  access_token=$(echo "$token_response" | node -e "console.log(JSON.parse(require('fs').readFileSync(0,'utf8')).access_token)")
  c_nonce=$(echo "$token_response" | node -e "console.log(JSON.parse(require('fs').readFileSync(0,'utf8')).c_nonce)")

  # 3. Construir el proof JWT ES256 (adaptado del patrón ya documentado en
  #    docs/dpg/inji-certify-preauth.md §2, paso 4).
  local proof_jwt
  proof_jwt=$(node "$(dirname "${BASH_SOURCE[0]}")/build-proof-jwt.mjs" "$c_nonce" "$CERTIFY_URL")

  # 4. Pedir la credencial.
  local credential_response
  credential_response=$(curl -sf -X POST "$CERTIFY_URL/v1/certify/issuance/credential" \
    -H "Authorization: Bearer $access_token" \
    -H "Content-Type: application/json" \
    -d "{
      \"credential_configuration_id\": \"MTCDrivingLicenseMDL\",
      \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"$proof_jwt\"}
    }")

  # 5. Extraer el CBOR base64url y decodificarlo a archivo binario.
  #    NOTA: si Inji Certify envuelve la respuesta como {docType,
  #    issuerSigned} (hallazgo 5 del spec), este paso lo detecta y avisa —
  #    no lo corrige (fuera de alcance de la Fase 1), solo documenta el
  #    hallazgo para que el operador lo vea.
  echo "$credential_response" | node "$(dirname "${BASH_SOURCE[0]}")/extract-cbor.mjs" \
    "$OUT_DIR/${label}.cbor"

  # 6. Verificar con el script de la Tarea 4.
  echo "=== Verificando $label ==="
  node "$VERIFY_DIR/verify-mdoc.mjs" "$OUT_DIR/${label}.cbor" "$OUT_DIR/iaca.pem" \
    --doctype=org.iso.18013.5.1.mDL --namespace=org.iso.18013.5.1
}

# Extraer la IACA que este entorno generó al arrancar (Inji Certify genera
# su propio par de claves/certificado en el primer boot cuando no se le
# provee uno — ver docs/mtc-mdl-poc/README.md §Riesgos sobre por qué esto
# NO es el certificado real del MTC).
docker compose -f "$(dirname "${BASH_SOURCE[0]}")/../docker-compose.yml" \
  exec -T certify cat /home/inji/CERTIFY_PKCS12/certify-root.pem \
  > "$OUT_DIR/iaca.pem" 2>/dev/null || {
    echo "AVISO: no se pudo extraer la IACA del contenedor automáticamente."
    echo "Verifica la ruta real del certificado dentro de /home/inji/CERTIFY_PKCS12/"
    echo "y ajusta este script — la ruta exacta depende de cómo Inji Certify"
    echo "nombra el certificado autogenerado en esta versión."
    exit 1
  }

issue_and_verify "MOCK-1CAT" "1categoria"
issue_and_verify "MOCK-4CAT" "4categorias"

echo ""
echo "=== Fase 1: AMBOS casos (1 y 4 categorías) verificados correctamente ==="
```

**Nota de riesgo explícita en el script:** la extracción de la IACA (`certify-root.pem`) es
una suposición sobre dónde Inji Certify v0.14.0 guarda su certificado autogenerado — no
verificada en este plan porque requiere ejecutar el entorno real, algo que corresponde a
quien ejecute esta tarea, no a quien la planifica. El script falla explícitamente con un
mensaje claro si la ruta no es correcta, en vez de fallar en silencio.

- [ ] **Step 2: Escribir el helper `build-proof-jwt.mjs`**

```javascript
// docs/mtc-mdl-poc/compose/scripts/build-proof-jwt.mjs
//
// Construye un proof JWT ES256 anónimo (sin kid/iss) para el flujo
// pre-authorized_code, siguiendo el patrón ya documentado en
// verifiably-go/docs/dpg/inji-certify-preauth.md §2 paso 4.
import { generateKeyPairSync, createSign } from 'node:crypto';

const [, , cNonce, audience] = process.argv;

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = publicKey.export({ format: 'jwk' });

const header = { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk };
const now = Math.floor(Date.now() / 1000);
const payload = { aud: audience, iat: now, nonce: cNonce };

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const signingInput = `${b64url(header)}.${b64url(payload)}`;

const sign = createSign('SHA256');
sign.update(signingInput);
sign.end();
const derSignature = sign.sign(privateKey);

// ECDSA DER -> raw (r||s) 64 bytes, formato que JWS ES256 exige.
function derToRaw(der) {
  let offset = 2;
  const rLen = der[offset + 1];
  offset += 2;
  let r = der.subarray(offset, offset + rLen);
  offset += rLen;
  offset += 1;
  const sLen = der[offset];
  offset += 1;
  let s = der.subarray(offset, offset + sLen);
  r = r.length > 32 ? r.subarray(r.length - 32) : Buffer.concat([Buffer.alloc(32 - r.length), r]);
  s = s.length > 32 ? s.subarray(s.length - 32) : Buffer.concat([Buffer.alloc(32 - s.length), s]);
  return Buffer.concat([r, s]);
}

const rawSignature = derToRaw(derSignature).toString('base64url');
console.log(`${signingInput}.${rawSignature}`);
```

- [ ] **Step 3: Escribir el helper `extract-cbor.mjs` (detecta el wrapper, avisa, no corrige)**

```javascript
// docs/mtc-mdl-poc/compose/scripts/extract-cbor.mjs
//
// Extrae el CBOR base64url de la respuesta JSON de Inji Certify y lo
// escribe a un archivo binario. DETECTA si viene envuelto en
// {docType, issuerSigned} (hallazgo 5 del spec) y lo AVISA — no lo
// extrae automáticamente, porque corregir el wrapper es trabajo de la
// Fase 2 (lado wallet), fuera de alcance de esta Fase 1. El script escribe
// el CBOR crudo tal cual llega, envuelto o no, para que el operador vea el
// problema real con sus propios ojos si aplica.
import { writeFileSync } from 'node:fs';
import { decode } from 'cbor-x'; // dependencia añadida en package.json de esta tarea

const [, , outPath] = process.argv;
let input = '';
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const response = JSON.parse(input);
  const credentialB64Url = response.credential;
  if (!credentialB64Url) {
    console.error('ERROR: la respuesta de Inji Certify no trae el campo "credential":');
    console.error(input);
    process.exit(1);
  }
  const cborBytes = Buffer.from(credentialB64Url, 'base64url');
  writeFileSync(outPath, cborBytes);

  try {
    const decoded = decode(cborBytes);
    if (decoded && typeof decoded === 'object' && 'docType' in decoded && 'issuerSigned' in decoded) {
      console.log('AVISO: el CBOR viene envuelto en {docType, issuerSigned} — hallazgo 5 del spec.');
      console.log('Esto es esperado en esta Fase 1 (la corrección vive en la Fase 2, lado wallet).');
      console.log(`El verificador de la Tarea 4 sobre este archivo FALLARÁ el parseo de IssuerSigned`);
      console.log('porque @owf/mdoc espera el mapa IssuerSigned directo, no el envoltorio.');
    }
  } catch {
    // Si no decodifica como CBOR aquí tampoco, el verificador de la Tarea 4
    // lo reportará con su propio mensaje de error — no duplicar el chequeo.
  }
});
```

- [ ] **Step 4: Añadir `cbor-x` como dependencia**

```bash
cd docs/mtc-mdl-poc/compose/scripts
npm init -y
npm install cbor-x
```

- [ ] **Step 5: Correr el script contra el entorno levantado en la Tarea 3**

Run: `bash docs/mtc-mdl-poc/compose/scripts/run-e2e.sh`

Expected: uno de dos resultados válidos, ambos informativos:
- Si el CBOR llega sin envolver: `All checks passed.` para ambos casos (1categoria,
  4categorias), terminando en `Fase 1: AMBOS casos (1 y 4 categorías) verificados
  correctamente`.
- Si el CBOR llega envuelto (hallazgo 5 esperado en v0.14.0 según el spec): el aviso de
  Step 3 se imprime, y `verify-mdoc.mjs` falla en "IssuerSigned decodifica bajo los esquemas
  de @owf/mdoc" — **este resultado también es un éxito de esta tarea**, porque confirma
  empíricamente en el entorno real (no solo por la documentación del spec) que el wrapper
  existe y exactamente cómo se manifiesta. El documento guía (Tarea 6) documenta cuál de los
  dos resultados ocurrió.

- [ ] **Step 6: Commit**

```bash
git add docs/mtc-mdl-poc/compose/scripts/
git commit -m "docs(mtc-mdl-poc): script end-to-end — emite y verifica mDL de 1 y 4 categorías"
```

---

### Task 6: Documento guía

**Files:**
- Create: `docs/mtc-mdl-poc/README.md`

**Interfaces:**
- Consumes: el resultado real de la Tarea 5 (Step 5) — qué pasó al correr el entorno
  completo, incluyendo si el wrapper apareció o no.
- Produces: el entregable final de cara al equipo del MTC/IUGO.

**Nota:** esta tarea no es código — es la escritura del documento que el spec (§Documento
guía) especifica. Se escribe DESPUÉS de las Tareas 1-5 porque debe reportar resultados
reales del entorno (Tarea 5), no hipotéticos.

- [ ] **Step 1: Escribir la estructura completa del documento**

```markdown
<!-- docs/mtc-mdl-poc/README.md -->
# PoC mDL — Licencia de Conducir MTC (ISO/IEC 18013-5)

Guía para que Inji Certify del MTC emita la Licencia de Conducir también como
**mDL conformante** (`mso_mdoc`), junto al SD-JWT que ya emite hoy — sin reemplazarlo.

Basado en la investigación y el código de `verifiably-go`
(`docs/superpowers/specs/2026-09-01-mtc-mdl-poc-design.md`), que ya implementó y validó
emisión mso_mdoc real contra Inji Certify v0.14.0 en un contexto distinto (walt.id como
emisor alternativo). Este documento adapta ese trabajo al despliegue real del MTC
(Inji Certify + Mimoto + InjiVerify + InjiWallet, CloudHSM real).

## Riesgos y supuestos a verificar (leer esto primero)

[... contenido de la sección §Riesgos y limitaciones conocidas del spec, transcrita y
adaptada con los resultados reales de la Tarea 5 — completar aquí con lo que realmente
ocurrió al correr run-e2e.sh: ¿apareció el wrapper CBOR? ¿la versión real del MTC es
v0.14.0? etc. Ver Step 2 de esta tarea.]

## Fase 1 — Emisión (validada en el entorno de pruebas de este repositorio)

[... pasos 1-7 del spec, con referencias a los archivos reales:
docs/mtc-mdl-poc/compose/certify/init-mdoc.sql, render-mdoc-template.mjs,
mock-fee-plugin/, docker-compose.yml, verify/verify-mdoc.mjs,
compose/scripts/run-e2e.sh — cada paso apunta al archivo concreto que lo implementa.]

### Cómo correr el entorno de pruebas

\`\`\`bash
cd compose
docker compose up -d
bash scripts/run-e2e.sh
\`\`\`

### Cómo adaptar esto al Inji Certify real del MTC

1. Confirmar la versión real de Inji Certify (`docker image inspect` sobre la imagen del
   ECR `inji-certify`) — si difiere de v0.14.0, los hallazgos de este documento deben
   re-validarse antes de confiar en ellos.
2. Confirmar si `certify.key_policy_def` ya tiene una fila `CERTIFY_VC_SIGN_EC_R1`
   (`SELECT app_id FROM certify.key_policy_def WHERE app_id = 'CERTIFY_VC_SIGN_EC_R1'`) —
   si no, aplicar el INSERT de `compose/certify/init-mdoc.sql` (Step 1) contra la base real.
3. Confirmar que `certify-default.properties` (o el properties real del MTC) tiene el
   mapeo `'ES256': {{'CERTIFY_VC_SIGN_EC_R1', 'EC_SECP256R1_SIGN'}}` — normalmente ya está
   (es parte del archivo base de Inji Certify, no algo agregado por este PoC).
4. **NO usar `certify-mtc-mock-fee.properties`** — extender el
   `MtcFeeDataProviderPlugin` real (repo `inji-dataprovider`) para que, cuando el
   `credential_config` activo sea `MTCDrivingLicenseMDL`, postee `driving_privileges` con
   la forma que `compose/certify/mock-fee-plugin/` simula — **confirmar primero contra una
   respuesta real del Servicio Web FEE que esa forma (array de objetos con
   `vehicle_category_code`/`issue_date`/`expiry_date`) es correcta** (ver riesgo de datos
   en la sección de riesgos).
5. Aplicar el `credential_config` de `init-mdoc.sql` contra la base real de Certify —
   revisando primero la decisión de modelado (una credencial con todas las categorías vs.
   una por clase, ver la sección correspondiente más abajo).
6. Obtener un certificado real de la CA MTC/RENIEC para la clave EC nueva
   (`generate-csr` / `upload-ca-certificate` / `uploadCertificate`) — **dependencia externa
   con plazo propio, no una tarea técnica de este documento**.
7. Identificar la IACA raíz real y documentar contra qué ancla de confianza validará un
   verificador de terceros el DSC — brecha abierta, no resuelta por este documento.

### Decisión de modelado: una credencial vs. una por clase

[... discusión documentada en la sección "Decisión de modelado a tomar en la Tarea 1" de
este plan — presentada aquí como una pregunta abierta para el equipo del MTC, no una
decisión ya tomada.]

## Fase 2 — Consumo en InjiWallet (bloqueada; procedimiento, no resultado)

[... transcribir la Fase 2 completa del spec (los 4 pasos, las opciones B/C sin decidir) —
esto es contenido a redactar, no una tarea de código, tal como el spec especifica en
§Alcance del plan de implementación.]

## Fase 3 — InjiVerify para mdoc (a investigar)

[... transcribir la Fase 3 completa del spec.]

## Portrait — limitación conocida, no arreglable desde este proyecto

[... transcribir el hallazgo 4 del spec — desensamblado de bytecode, conclusión cerrada.]

## Fuente de este documento

- Spec: `docs/superpowers/specs/2026-09-01-mtc-mdl-poc-design.md`
- Código de referencia: `verifiably-go/internal/adapters/injicertify/db.go`,
  `issuer.go`, `verifiably-go/internal/mdl/testdata/verify/verify.mjs`
- Documentos as-built del MTC (no versionados en este repo, aportados por el usuario):
  `resumen-tecnico-Inji-MTC.pdf`, `MTC-KT.pptx.pdf`,
  `Arquitectura-AWS-INJI-MTC-revision-as-built.pdf`
```

- [ ] **Step 2: Completar la sección de riesgos con el resultado real de la Tarea 5**

Editar la sección "Riesgos y supuestos a verificar" del `README.md` con el resultado
observado al correr `run-e2e.sh` en la Tarea 5 — específicamente, si el wrapper CBOR
apareció o no en la respuesta de Inji Certify v0.14.0 dentro de este entorno de pruebas.
Esto convierte el hallazgo 5 del spec (documentado ahí a partir de un spike previo, en un
contexto distinto) en algo re-confirmado por este propio entorno.

- [ ] **Step 3: Revisión de placeholders — leer el documento completo y confirmar que no
  quedan `[...]` sin rellenar**

```bash
grep -n '\[\.\.\.' docs/mtc-mdl-poc/README.md
```

Expected: sin resultados (todos los placeholders de la plantilla del Step 1 fueron
reemplazados por contenido real).

- [ ] **Step 4: Commit**

```bash
git add docs/mtc-mdl-poc/README.md
git commit -m "docs(mtc-mdl-poc): documento guía completo para el equipo MTC/IUGO"
```

---

## Self-Review (completado antes de entregar este plan)

**1. Cobertura del spec:**
- §Fase 1 pasos 1-7 → Tareas 1 (pasos 1-2), 2 (paso 4 riesgo de datos), 3 (paso 5 CloudHSM
  documentado como fuera de alcance del entorno local), 5 (paso 7 criterio de cierre).
- §Entorno de pruebas reproducible → Tarea 3.
- §Documento guía → Tarea 6.
- §Fase 2, §Fase 3 → contenido transcrito en la Tarea 6 (Step 1), NO tareas de código,
  conforme a §Alcance del plan de implementación del spec.
- §Criterios de aceptación (Fase 1) → Tarea 5, Step 5.
- §Riesgos y limitaciones → Tarea 6, Step 2 (completado con resultado real, no hipotético).

**2. Placeholder scan:** sin TBD/TODO en ningún paso de código. La Tarea 6 sí contiene
placeholders `[...]` deliberados en su Step 1 — son la plantilla del documento, resueltos
explícitamente en el Step 3 de esa misma tarea antes del commit.

**3. Consistencia de tipos/nombres:** `credential_config_key_id = 'MTCDrivingLicenseMDL'`
usado consistentemente en Tareas 1, 3, 5, 6. `verify-mdoc.mjs` (Tarea 4) y su invocación en
`run-e2e.sh` (Tarea 5) coinciden en la firma CLI (`<cbor> <iaca-pem> [--flags]`).
`mock-fee-plugin-1.0.0.jar` (Tarea 2) referenciado con la misma ruta en el volumen de la
Tarea 3.
