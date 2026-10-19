# Release Notes

Every stable release requires its own `docs/releases/vX.Y.Z.md` file in the
exact commit being released. The signed-release workflow checks that the file
exists before building and uses its contents as the GitHub release body.
Do not reuse a generic release description or publish an empty placeholder.

Write concise, version-specific release notes in English. Do not add a Persian
translation unless explicitly requested. Keep descriptions limited to core
runtime responsibilities; do not describe host infrastructure management as a
core feature. Write operator-focused notes covering:

1. A short Summary explaining the problem and outcome.
2. A Changes section listing every meaningful change in the current version,
   including relevant fixes, persistence changes and regression coverage.
3. Brief Compatibility and Security notes for behavior changes, preserved
   controls, migration requirements and important limitations.
4. Short Validation and Upgrade notes: verified results, expected interruption,
   verification and rollback. Do not invent test or deployment results.
5. A source comparison link; reference signed artifacts when relevant.

Prefer bullets and avoid repeating the same change across sections. Keep the
main description around 250-400 words unless a complex migration needs more.
Keep essential operational/security caveats even when shortening the prose.

Describe behavior in the release's own code, not unrelated panel changes.
Never include production addresses, customer identifiers, credentials or private
incident captures. Preserve binary assets, tags and signed catalogs when editing
the prose of an already-published release. Correct inaccurate notes explicitly.
