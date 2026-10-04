# Documentation

The manuals explain installation, operation and recovery.
The design specification defines behavior and compatibility; the development documents define how to change and validate wgft.

| Task | Documents |
| --- | --- |
| Install or operate wgft | [User manuals](manual/README.md), [CLI reference](cli.md) |
| Understand behavior and compatibility | [Design specification](design/README.md) |
| Change or test the implementation | [Development documents](development/README.md), [project conventions](../CLAUDE.md) |

## Revision and release

These documents describe the revision checked out with them.
The `main` branch can contain changes that have not been released.
For a deployed release, read the documents at its matching Git tag and the release notes before applying an update.
Proposals and past validation results have their own status; they do not establish implemented behavior for the current revision.

## Finding a specific answer

Choose a task above, then open the relevant guide or specification section.
For implementation work, read the project conventions and the affected test requirements before making changes.
When a decision needs historical evidence, use the topic's history entry to select the relevant record.
Normal searches under `docs/` select current documents through `docs/.ignore`.
Search a selected history directory explicitly when checking an older decision.

[日本語](README.ja.md)
