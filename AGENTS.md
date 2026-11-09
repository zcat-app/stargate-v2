# Repository and publication rules

These rules apply to the entire repository. Follow explicit user instructions
when they impose a stricter boundary. If a file's publication status is unclear,
ask before including it in a commit, release, upload, or public change.

## Public content boundary

- Public content is product source, necessary tests, reusable configuration
  examples, user/operator instructions, licenses, required attribution, and
  explicitly approved product artwork.
- Never publish private operator or user identities, personal home-directory
  paths, deployment hostnames or addresses, real endpoints used during testing,
  access codes, passwords, tokens, private keys, saved browser profiles, device
  grants, operational state, or credentials.
- Internal session notes, conversation transcripts, planning records, AI review
  receipts, approval history, raw test/scan results, benchmark run journals,
  debugging evidence, and pre-release investigation/repair history stay private.
  They do not become public documentation because they are under `docs/`.
- Store submission instructions, upload checklists, submission-only screenshots,
  audit reports, and submission/upload-only packaging or preparation utilities
  stay local and Git-ignored unless the user explicitly approves their inclusion
  in the public project. Reusable product build and distribution tooling belongs
  with the product source.
- Use reserved example domains and synthetic values in public examples. Preserve
  necessary public upstream endpoints, trust anchors, licenses, and legal credits;
  do not replace them with a real operator's data or private test infrastructure.
- Do not put prohibited private values into tracked rules, tests, scan
  configurations, or CI as a deny-list. Keep any exact private deny-list outside
  version control, and report a match's location without printing its value.
- Screenshots must omit per-profile UUIDs, capture-specific extension registration
  IDs, local manifest/inspection URLs, and private installation paths. These can
  violate the publication boundary even when they are not credentials. Capture a
  suitable UI state or omit the identifying region or image.

## Security documentation

- Public security documentation explains current protection limits, supported
  use, unresolved release-relevant risks, and required user actions.
- Issues found and fixed before the first public release belong in internal
  investigation records. Do not present pre-release repair history as a current
  vulnerability or publish internal scanner/query chronology.
- If an issue affected a public release, retain an accurate, concise advisory:
  affected versions, fixed version, impact, and the action users must take.
  Preserve necessary upgrade/recovery instructions. Do not infer affected or
  fixed versions without checking release and artifact provenance.
- Scanner matches require classification against the exact released bytes.
  Distinguish live credentials from public hashes, parser delimiters, synthetic
  fixtures, and upstream self-test constants. An empty scan or a past fix is not
  a current security assessment. State uncertainty and verification limits.

## Work locally without publishing private material

- Keep private audit evidence, reviewer outputs, store assets, and preparation
  documents outside the repository or explicitly Git-ignored from creation.
  Check `git check-ignore` and `git status`; untracked does not mean ignored.
- Ignoring a tracked file does not unpublish it. Identify whether it needs
  sanitizing, untracking, removal from release payloads, or historical cleanup.
- Preserve unrelated user changes and existing private evidence. Do not delete
  whole directories or rewrite history as an assumed cleanup shortcut.
- Stage only the intended files. Do not use blanket staging to publish a
  development checkout. Inspect every new file and the complete staged diff.
- Before changing private/deployment examples, check whether actual guides or
  tests consume the text. Keep functional instructions and meaningful tests
  while removing private values and internal process records.

## Verify the actual public surface

- Identify the intended public repository, branch/tag, and exact commit first.
  A private development checkout may differ from the sanitized public source.
  Do not treat a local finding as proof of public exposure, or a clean local
  scan as proof that published material is clean.
- Review the exact publication candidate and the actual retrievable public
  surfaces: current files, relevant history and obsolete commit references,
  branches/tags, release descriptions and payloads, nested archives, every
  container-image layer, CI logs/artifacts, and published images/metadata.
  Check any additional public surfaces implicated by the task.
- Verify downloaded artifact hashes and inspect the bytes users receive. Check
  screenshots visually as well as their metadata. Links must work in a clean
  public export without depending on ignored research or private local files.
- Exact-string searches alone are insufficient. Inspect credential candidates,
  encoded content where relevant, private-state files, internal narratives, and
  real testing links. Record coverage and any uninspected or inaccessible areas.
- Treat old commits, cached views, CI references, and existing release archives
  as separate publication surfaces. A clean current branch, changed tag, deleted
  file, or added ignore rule does not prove old public material is inaccessible.
- Keep findings and evidence private. Do not create a public incident or audit
  document containing the very identifiers, endpoints, or secrets being removed.

## Review and completion

- Complete the user-requested independent reviews at the requested effort on
  the exact candidate and evidence. Reviewers must inspect underlying material,
  challenge scanner classifications and coverage, and report open findings.
  Re-review material changes before relying on an earlier approval.
- Never report "no leaks", "clean", "fixed", or equivalent beyond what was
  actually verified. Distinguish confirmed exposure, private-only findings,
  unresolved policy questions, and limits of the audit.
- Prepare a concrete remediation before requesting approval. Public visibility
  changes, destructive remote deletions, force-pushes, history rewrites, and
  external outreach require explicit authorization for the proposed action.
  Do not claim deletion can erase already downloaded or third-party copies.
- If the user pauses work, stop further actions and pause active reviewers.
  Resume only when the user authorizes continuation.
