## ADR-084: A volume that this release cannot serve stops deploy
- Status: Proposed
- Owner: CDPI Architects
- Scope: The stack secrets check of `vca doctor`, the upgrade path of `vca setup` and `vca dpg upgrade-secrets`, and the checks of `vca deploy` before `docker compose up`.
- Extends: ADR-055 decision 1.
- Context: The release before generated secrets ran the Certify database as the user `certify` in the database `certify`. It ran Inji Verify on a database with no `init.sql`. This release runs Certify as the user `postgres` in `inji_certify`. Its init files lay the schemas out at the first start of a volume. A Postgres volume keeps the user, the database and the password of its first start. So a volume of that release cannot serve this one on any password. Certify then fails to authenticate and its health check never passes. `vca deploy` reports an unhealthy container after a minute with no cause.
- Decision:
  1. A stack volume names what this release changed inside it. The name says why a volume of the release before generated secrets cannot serve this one. Today that is `vca_inji-certify-db` and `vca_inji-verify-db`.
  2. `vca setup` gives such a volume no old password. It names the volume and the change. It prints the two commands that save the volume as a tar file and remove it. `vca dpg upgrade-secrets` does the same and writes nothing for it.
  3. `vca doctor` fails the stack secrets check for such a volume with the same commands.
  4. `vca deploy` runs the stack secrets check before `docker compose up` and stops with its words. It reads the volumes through `docker volume ls` and `docker volume inspect`, as the doctor does.
  5. The check also fails a stack `.env` that holds the default password of the earlier release while no volume holds it. A new volume must start on a generated password. The fix names the line to remove and `vca setup`.
  6. VCA removes no volume. The operator runs the commands.
- Consequences:
  1. A host that ran the earlier release removes its Certify and Inji Verify volumes once. The earlier release wrote their data under another layout, so it does not carry over.
  2. `vca deploy` reads the volumes of each stack of the selected pairs on every run. That is two `docker volume` commands per volume.
  3. A later release that changes the layout of a volume again names it the same way.
