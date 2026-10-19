# Release Notes

Every stable release requires its own `docs/releases/vX.Y.Z.md` file in the
exact commit being released. The signed-release workflow checks that the file
exists before building and uses its contents as the GitHub release body.
Do not reuse a generic release description or publish an empty placeholder.

Write operator-focused notes covering:

1. Summary and the concrete problem addressed.
2. Detailed changes, grouped by affected runtime component.
3. Behavior changes, compatibility and persistence/migration implications.
4. Preserved security controls and any changed availability/security tradeoff.
5. Validation actually completed, with its limits clearly distinguished from
   production observations. Do not invent test or deployment results.
6. Upgrade procedure, expected per-core interruption, verification and rollback.
7. Known limitations and changes explicitly not included.
8. Source commit or comparison link and the signed artifact/catalog information.

Describe behavior in the release's own code, not unrelated panel changes.
Never include production addresses, customer identifiers, credentials or private
incident captures. Preserve binary assets, tags and signed catalogs when editing
the prose of an already-published release. Correct inaccurate notes explicitly.
