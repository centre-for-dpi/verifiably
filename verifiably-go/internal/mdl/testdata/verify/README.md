# Harness de verificación independiente

Verifica que los mdocs emitidos por `internal/mdl` son aceptados por una
implementación que no es la nuestra (`@owf/mdoc`, de OpenWallet Foundation,
la misma que usa Credo).

Si ambos lados compartieran implementación, una mala lectura del estándar
pasaría los dos y el error se descubriría en la demo.

Esto ya rindió: la primera ejecución rechazó nuestro mdoc porque `IssuerAuth`
salía envuelto en el tag CBOR 18 (`COSE_Sign1_Tagged`). ISO/IEC 18013-5 lo
define como un `COSE_Sign1` **sin** tag — el mapa `IssuerSigned` que lo
contiene ya lo identifica. `go-cose` siempre emite la forma etiquetada, así
que `SignMSO` ahora la quita (`untagSign1`). Ningún test propio detectó esto:
usábamos el mismo `go-cose` para firmar y para verificar.

## Uso

```bash
# 1. Generar los vectores desde Go
cd ../../../..                      # hasta verifiably-go/
MDL_WRITE_VECTORS=1 go test ./internal/mdl/... -run TestGenerateVectors

# 2. Verificarlos con @owf/mdoc
cd internal/mdl/testdata/verify
npm ci        # npm install la primera vez
npm run verify
```

Con Docker (si Go o Node no están instalados):

```bash
# vectores
docker run --rm -e MDL_WRITE_VECTORS=1 -v "$PWD":/app -w /app golang:1.25-alpine \
  go test ./internal/mdl/... -run TestGenerateVectors -v

# harness
docker run --rm -v "$PWD/internal/mdl/testdata":/td -w /td/verify node:22-alpine \
  sh -c "npm ci && npm run verify"
```

## Qué verifica de verdad

`@owf/mdoc` es deliberadamente agnóstico de criptografía: no hace X.509 ni
COSE por sí mismo, sino que llama a un `MdocContext` que provee el host.
`verify.mjs` lo implementa sobre `node:crypto` — una tercera implementación
independiente de las primitivas — de modo que nada en la cadena de confianza
depende de nuestro código Go.

El núcleo es `IssuerSigned.decode(bytes)` seguido de `issuerSigned.verify()`,
que emite 22 aserciones (`VerificationAssessment`). Se recogen todas en vez de
lanzar en la primera, para no enmascarar fallos posteriores:

- **Firma COSE_Sign1 real** del MSO contra la clave pública del DSC.
- **Cadena X.509 real** DSC → IACA, anclada en `iaca.pem`: cada certificado
  debe estar firmado por el siguiente y el último debe encadenar a un ancla
  de confianza, todo válido en la fecha de verificación.
- **Los 12 digests recalculados**: cada `IssuerSignedItem` se vuelve a
  hashear y se compara con el commit en `valueDigests`. El harness además
  comprueba que hubo exactamente 12 comparaciones, para que un namespace
  vacío no pase por vacuidad.
- **Ventana de validez** del MSO contra la validez del propio DSC y contra el
  reloj actual.
- **Control negativo**: el mismo mdoc debe *fallar* anclado al DSC (una hoja,
  no una CA). Sin esto, un bug en `verifyCertificateChain` que siempre
  aceptara pasaría inadvertido.

Encima de eso, comprobaciones estructurales sobre el MSO ya parseado: docType,
namespace ISO, 12 elementos comprometidos y 12 divulgables, `validUntil` que
no excede `expiry_date`, presencia de la device key (sin ella la credencial es
clonable) y el marcado `POC-DO-NOT-TRUST` en ambos certificados.

Lo que **no** cubre: `DeviceSigned` / device auth (no hay wallet todavía) y
las listas de estado/revocación (el MSO no lleva `status`, así que
`disableStatusValidation` evita un fetch de red que no aplica).

`verifyCertificateChain` es una implementación del harness, no un validador
X.509 completo: comprueba enlace de firmas, ventanas de validez, anclaje y que
el ancla sea CA, pero **no** name constraints, path length ni key usage.

## Caducidad de los vectores

Los certificados de los vectores caducan de verdad: Annex B limita un DSC a
457 días y `internal/mdl/pki` lo impone. El generador usa ese máximo (y da 3
años a la IACA, porque `GenerateDSC` rechaza un DSC que sobreviva a su
emisor). No se puede evitar la caducidad — sólo hacerla visible a tiempo:

- `TestVectorsHaveUsefulRemainingLife` (Go, corre en CI normal) falla cuando
  quedan menos de 60 días.
- El harness comprueba lo mismo (`DSC has at least 60 days of validity left`).

Cuando fallen, regenerar los vectores y actualizar los tres repos en el mismo
cambio.

### Verificar en una fecha simulada

`MDL_VERIFY_NOW` fija el reloj de verificación, para comprobar que los
vectores siguen siendo válidos en el futuro y no sólo hoy:

```bash
MDL_VERIFY_NOW=2027-11-01T00:00:00Z npm run verify
```

Sólo puede endurecer el resultado, nunca relajarlo: `now` alimenta las
comprobaciones de validez del certificado y del MSO. Pasada la caducidad del
DSC el harness falla con las dos aserciones esperadas ("Issuer certificate
must be valid" y "Unable to determine a trusted issuance chain"), que es
exactamente el error confuso que esta política evita que aparezca por sorpresa
aguas abajo.

### Cómo saber que el harness no miente

Se probó con mutantes: un bit cambiado en la firma, y `family_name` alterado
de `Pérez` a `Qérez` (misma longitud, CBOR válido). El primero falla la
aserción de firma; el segundo falla el digest de `family_name` por nombre.
Un harness que imprime PASS sin comprobar nada es peor que no tener harness.

## Contrato con otros repos

Los archivos de `../vectors/` son el contrato ejecutable con `cdpi-wallet` y
la app reader: los copian como fixtures de test. Si el formato del mdoc
cambia, sus tests fallan y la divergencia se detecta sola.

Al regenerar los vectores hay que actualizarlos en los tres repos en el mismo
cambio. `package-lock.json` se versiona a propósito: el harness es parte de
ese contrato y debe correr con las mismas dependencias en los tres repos y en
CI.

Los vectores contienen sólo material público — los dos certificados y el
mdoc. Las claves privadas nunca se escriben a disco.
