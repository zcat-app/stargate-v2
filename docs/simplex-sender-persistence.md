# SimpleX sender startup persistence

The dedicated alert runtime uses `unless-stopped`, like the four route
containers. Docker can restart it after host boot or process failure; a deliberate
container stop keeps it stopped. This policy does not run the monitor, create an
alert event or replay accepted/uncertain delivery state. No readiness health check
is supplied, so a running runtime does not establish contact readiness or delivery.

## Existing installation: separate activation

Updating a Compose source file does not change an existing container. Schedule
a short sender recreation while retaining its exact image, private profile,
recipient and durable delivery state.

The reviewed activation must:

1. Verify the exact existing image, standalone project, profile bind, recipient,
   UID, constraints and private source configuration. Pause the daily timer and
   confirm no active monitor or unresolved delivery. Back up state and receipts.
2. Apply only the reviewed restart-policy change to the operational Compose
   source used by the installed monitor. Render with its existing private
   profile/recipient settings and retain an image override pinned to the existing
   immutable image. Stop on any other configuration change.
3. Recreate only the sender with that same image/profile/recipient, explicitly
   disabling builds and pulls. This briefly reconnects the existing runtime;
   it does not restart the app, Tor, I2P or Nym. Keep the standalone project.
4. Require the new container's image, profile bind, environment and protections
   to match, `unless-stopped` to be active, and its Compose hash to agree with
   the reviewed source/override. A new container ID is expected.
5. Verify the ledger, baselines and all old receipts stayed byte-identical and
   no monitor invocation/event/send was created. A running runtime alone does
   not establish contact readiness or phone receipt.
6. Restore the existing daily timer only after success, checking that a missed
   persistent trigger cannot cause an unapproved catch-up. On failure, preserve
   delivery state and hold scheduling; do not clear markers or replay alerts.

Preserve the previous complete configuration and same-image recovery command.
If recreation or profile loading fails, record the failure and inspect before
any separately approved recovery. Do not restore an old profile database or ledger
over newer state. Update the installation record with the new sender ID before
checking host-reboot recovery; keep its identity and policy checks intact.

Ordinary web remains on Nym; the sender remains a standalone alerts-only service.
