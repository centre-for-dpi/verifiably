# Decisión: el emisor nativo Go (`feat/mdl-issuer`) es el camino de producción para mDL

Status: **decidido.** Resuelve la pregunta que
`2026-08-20-mdl-production-path-analysis.md` dejó explícitamente abierta en
su tabla comparativa — cuál de los tres caminos a un mDL conforme (legacy
`issuer-api` parcheado, `issuer-api2` de walt.id, o el emisor nativo Go)
absorbe a los otros. Este documento no repite ese análisis; lo asume leído
y solo registra la decisión y sus consecuencias inmediatas.

## Decisión

El emisor nativo Go, `internal/mdl/` en la rama `feat/mdl-issuer`, es el
camino de producción. `issuer-api2` de walt.id deja de perseguirse como
backend de producción para mDL — el trabajo ya hecho con él (certificados
de prueba, portrait real, verificación end-to-end) queda como lo que
siempre fue útil para: validar que el reader/wallet/pipeline de verificación
funciona con un mdoc conforme real, no como el emisor que termina en manos
de un ciudadano real.

## Por qué, en una frase

Es el único de los tres caminos que no depende de un segundo servicio de
terceros con bloqueadores de seguridad duros sin resolver (API de gestión
sin autenticar, claves privadas de ejemplo comprometidas en el repo público
de walt.id — ambos documentados en el ADR de análisis), y mantiene la
consistencia arquitectónica que el proyecto ya persigue: `verifiably` como
middleware con adaptadores propios, no atado a la superficie de un DPG
específico.

## Lo que esto NO decide

- **No** decide que walt.id deja de usarse en absoluto — `issuer-api`/
  `issuer-api2` siguen siendo adaptadores válidos para otros tipos de
  credencial (W3C VC, SD-JWT) donde ya son el camino existente y no tienen
  los mismos bloqueadores de seguridad que el mdoc de `issuer-api2`
  específicamente hereda de su propia configuración de ejemplo.
- **No** decide que el emisor nativo está listo para producción hoy. Según
  el ADR de análisis, le falta: datos reales del solicitante en vez de
  placeholders hardcodeados (`birth_date`, `issuing_country`,
  `issuing_authority`, `driving_privileges` son literales o derivaciones de
  `now`), persistencia del IACA/DSC entre reinicios (hoy se regenera en
  cada arranque del proceso, invalidando todo lo emitido antes),
  integración al catálogo de esquemas del operador (hoy es un endpoint
  separado, `POST /api/v1/credentials/mdl/issue`, invisible al resto de la
  plataforma), y auditoría (`APIMdlIssue` nunca llama `apiRecordIssuance`).
- **No** resuelve custodia de llaves (HSM/KMS) ni multi-tenencia
  (una autoridad emisora por proceso hoy) — gaps compartidos con los otros
  dos caminos, no específicos de esta decisión.

## Consecuencia inmediata

Los datos de prueba de `issuer-api2` (el mDL austriaco de muestra que se
usó para validar C.7.3b y presentaciones BLE) siguen siendo válidos como
fixture de prueba para el reader/wallet — no hay que re-emitir nada solo
por esta decisión. Lo que cambia es hacia dónde apunta el trabajo de
desarrollo siguiente: cerrar los gaps de la lista de arriba en
`internal/mdl/`, no seguir invirtiendo en resolver los bloqueadores de
seguridad de `issuer-api2`.

## Próximos pasos concretos, en orden

Estos son nuevos — no estaban en `2026-08-20-mdl-tramo-c-status-and-next-steps.md`
porque esa decisión aún no existía cuando se escribió.

1. **Datos reales del solicitante.** Reemplazar los literales hardcodeados
   en `mdlLicenceFromClaims` (`mdl_issue.go:185-207`) por un modelo de
   entrada real — probablemente extendiendo el mecanismo de `subject_data`
   que ya existe para otros tipos de credencial, en vez de inventar uno
   nuevo solo para mdoc. Incluye resolver de dónde viene la foto (Parte 5
   del ADR de análisis: hoy ningún data source del repo tiene una columna
   de foto).
2. **Persistencia del IACA/DSC.** `NewServerSigner` genera una raíz nueva
   en cada arranque (`serversigner.go:24-38`) — el bloqueador más simple de
   resolver primero (probablemente: cargar de un secreto/volumen
   persistente si existe, generar y persistir si no) y el que más rápido
   destraba pruebas repetibles.
3. **Integración al catálogo de esquemas.** Convertir el endpoint separado
   en algo que el operador pueda descubrir/configurar como cualquier otro
   tipo de credencial, no un caso especial.
4. **Auditoría.** Wire `apiRecordIssuance` en `APIMdlIssue`.

Cerrar C.7.1 formalmente (PR #13, `go vet`/`gofmt`, revisión) sigue siendo
trabajo independiente y más urgente que cualquiera de estos — el código que
el PR protege ya es correcto y no depende de esta decisión.

## Fuentes

- `2026-08-20-mdl-production-path-analysis.md` — el análisis completo que
  esta decisión resuelve; tabla comparativa, verdicts por parte, todo
  citado a archivo/línea real.
- `2026-08-20-mdl-tramo-c-status-and-next-steps.md` — mapa de estado que
  esta decisión actualiza (su paso "1. Decidir cuál de los dos caminos a
  portrait es el definitivo" queda resuelto por este documento).
