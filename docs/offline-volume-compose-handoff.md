# Handoff imported volumes to an isolated Compose project

This procedure maps the successful output of [the offline Docker volume importer](offline-volume-import-docker.md) to a new Compose project. It does not start a container, remove the recovery gate, prepare credentials, or establish that the restored installation is safe to expose. Complete the import document's **Prepare the imported app-data volume** procedure, then the [offline I2P control fleet reset](offline-i2p-fleet-reset.md), before considering activation. Keep the original installation and all other copies offline; make the operator decisions required by [offline staged recovery](offline-staged-recovery.md), including identity continuity, port history, matching data and compatibility.

The same exclusive local Docker daemon, trusted Docker administrator and offline-source assumptions apply throughout validation, configuration review and any activation. A competing daemon client can change resources between checks and use; these checks cannot provide a lock, prove data authenticity or stop a privileged actor. Docker daemon identity can remain the same after a restart. A matching ID does not prove that the daemon did not restart. Neither a successful import nor this handoff verifies I2P identity, network routing, compatibility, credentials or readiness for service. The application receives no Docker socket.

Build and test the Java tools using the [adapter guide](../backup-docker-tools/README.md). Synthetic checks do not establish production restoration or compatibility with every Docker daemon or Compose installation.

For a successful [authenticated archive import](offline-archive-import-docker.md), the same command accepts its distinct journal schema and validates its actual stopped `init` and `archive` helpers, scratch volume, and recorded volume creation identities. The scratch volume is excluded from the Compose override and retains staged plaintext.

The handoff requires the original successful private Java-import journal and **both stopped importer helper containers** to remain present. Java journals also require their retained private JAR snapshots; Java archive journals require their retained authenticated plaintext spool, which is rehashed on each handoff. The tool checks the journal's completed event sequence and deterministic mapping, the recorded daemon ID, each existing volume's exact role and import labels, local driver, scope and options, the two stopped helper IDs, and that no other container is attached to the imported volumes. It also checks for already labeled or conventionally named resources for the derived project. It makes only inspection calls. It does not verify volume contents, inspect the recovery gate or prepare an image. Only the supported Java import journal schemas are accepted; unknown or retired schemas are rejected before Docker inspection. If helper containers or retained files were removed, or validation fails or is ambiguous, stop and independently investigate; do not invent a new mapping or create volumes to satisfy the checks.

Use an absolute journal path and a private directory for the output. Review the generated file and preserve it unchanged. The output is JSON, which Docker Compose accepts as YAML; every imported volume is declared `external: true` with its exact imported name. Compose therefore must find those names instead of creating missing volumes. For a five-volume import the override additionally reserves `nym-data` and `nym-secrets` as external volumes with deliberately absent `stargate-unavailable-<token>-...` names. The handoff checks these names are absent: if the Nym overlay is accidentally added, Compose should fail rather than create empty Nym volumes. This is not an atomic activation guard: other resources or services might already have been created or started, and a competing client or later override can defeat the check. Keep Nym disabled for five-volume imports and review the merged configuration. External names and labels are not immutable identities; replacement after validation still requires the exclusive-daemon assumption.

```sh
umask 077
JOURNAL=/absolute/private-journals/stargate-import-REPLACE_WITH_TOKEN.jsonl
OVERRIDE=/absolute/private-directory/recovery-compose.json
tools/offline_volume_compose_handoff.sh \
  --journal "$JOURNAL" --ack-exclusive-local-daemon > "$OVERRIDE"
```

Proceed only if that command exits zero and the output is complete. A failed command can leave an empty or partial output file; discard it. The `name` field is `stargate-recovery-` followed by the journal token. Set `PROJECT` to that exact value. Use exactly the base Compose file and this override for five volumes; when the original import used `--nym`, include `compose.nym.yaml` between them and satisfy its provider setting. Do not enable Nym with a five-volume import. The following five-volume example is **inspection only**:

```sh
PROJECT=stargate-recovery-REPLACE_WITH_TOKEN

docker --host unix:///var/run/docker.sock compose \
  --project-name "$PROJECT" -f compose.yaml -f "$OVERRIDE" config
```

For seven volumes add `-f compose.nym.yaml` before `-f "$OVERRIDE"`. Inspect the merged configuration before proceeding: the project name must match, each of the five (or seven) active volumes must be external and resolve to its journaled name, and each service must mount the correct roles at the expected paths from the checked-in Compose files. Check all other mounts, images, ports, networks, environment values, profiles and any interpolation or Compose environment settings as well. Verify trusted, compatible local service images and host port availability; avoid extra overrides or environment settings that change the reviewed configuration. This manual review is required: the handoff tool does not inspect the merged Compose configuration or image contents. The recovery project name does not by itself guarantee isolation from the original's ports, networks or external resources.

Immediately before any separately chosen activation, while exclusive control is maintained, rerun the handoff into a different private file and compare it with the reviewed override. Check both commands' exit status:

```sh
CHECK=/absolute/private-directory/recovery-compose-check.json
tools/offline_volume_compose_handoff.sh \
  --journal "$JOURNAL" --ack-exclusive-local-daemon > "$CHECK" && \
  cmp -s "$OVERRIDE" "$CHECK"
```

Only if credential recovery, the offline I2P fleet reset, configuration review and recheck all succeed may the operator deliberately use the same `--project-name` and `-f` arguments with a Compose activation command. Activation may create project resources and expose configured services; this tool never performs it. After activation the project's resources and attachments will cause the handoff validation to fail by design, so do not use it as a routine restart check. If an activation or any check fails, keep the original offline and inspect the precise project resources and imported volumes before acting. This procedure provides no atomic rollback, secure erasure, protection from storage failure or assurance against another Docker administrator.
