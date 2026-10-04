# Documentation maintenance

[日本語](documentation.ja.md) · [Development documents](README.md)

## Sources and scope

Repository documents describe the checked-out revision; main can include unreleased changes.
Use the matching Git tag and release notes for a released version.
The [manuals](../manual/README.md) explain verified installation and operation, the [design specification](../design/README.md) defines behavior and compatibility, and the [testing policy](testing.md) defines required checks.
The [test catalog](testing-catalog.md) identifies missing tests and limits of verification; the [lab instructions](../../lab/README.md) explain execution.
Read the project conventions and the affected topic before changing it.

Current documents retain constraints, unimplemented proposals and the reasoning needed to understand a decision.
Use Git history for previous specifications and completed plans, pull requests for change rationale and detailed validation, and release notes for changes between releases.
Keep working drafts on the working branch and state proposed or unimplemented behavior explicitly.
A merged document does not establish that its implementation exists or has been verified.

## Adding or changing documents

1. Update the page that owns the subject and link to it from related pages instead of repeating policy.
2. For a changed decision, revise the current design before implementation. Inspect code and relevant tests before describing behavior as available. Execute published procedure commands in the lab or on the relevant hardware, and mark unverified environments and missing implementation explicitly.
3. Keep English/Japanese pairs equivalent in structure and information, with reciprocal language links. Japanese-only design bodies may remain single-language; their bilingual indexes identify the language.
4. Keep indexes focused on current topics. Remove completed plans and detailed experimental records from current documents, retaining necessary rationale in the relevant topic and the detailed evidence in Git or the pull request.
5. Preserve published paths and fragments with compact forwarding pages or explicit anchors. Register maintained legacy stubs and anchors in `scripts/check-docs-policy.json`.
6. Run the documentation checks and apply the [testing policy](testing.md) to changes involving scripts or fixtures.

## Update milestones

- Decision:Update the current contract and retain the rationale and unverified assumptions needed to understand it.
- Implementation:Check code and tests, remove pending labels only for implemented behavior, and update affected manuals and caveats. Record validation results and measurements in the pull request.
- Release:Check documents against the tagged implementation, update README status and release notes, and review upgrade instructions and platform caveats.

Do not append a separate revision log to the public documents.
Earlier text remains available in Git history.

## Generated reference and images

Do not edit `docs/cli.md` manually.
Change `cmd/wgft/helptext.go` and regenerate the reference in the same commit:

```sh
go test ./cmd/wgft -run TestCLIDocUpToDate -update
```

`TestCLIDocUpToDate` checks agreement with help and requires examples for executable commands.
Describe help behavior only after laboratory verification.
READMEs link to the reference and `wgft <command> --help` instead of repeating command tables.
After changing Web UI templates, text or sample data, run `scripts/screenshot-ui.sh` and inspect the image diff; its header defines prerequisites and procedure.
Use Mermaid for README diagrams.

## Automated checks

```sh
python3 scripts/check-docs.py
python3 scripts/check-docs-test.py
bash scripts/check-ascii-punct.sh
```

`lint-output` runs documentation checks on every push and pull request, including document-only changes.
The checker reads tracked Markdown and checks relative file links, Markdown fragments, explicit anchors, duplicate heading slugs and reference links.
It ignores fenced code, inline code and comments, and does not fetch external URLs.
Non-Markdown fragments, rendered HTML links and exotic Markdown extensions are outside its scope.
Generated CLI examples are checked by their Go test; links to CLI headings remain checked.

Pairs use `.ja.md` filenames or reciprocal `<!-- docs-pair: other-file.md -->` comments.
The checker verifies pair existence and reciprocal links or declarations, not translation quality.
Old forwarding pages use `<!-- docs-status: deprecated -->` and the legacy registry preserves their paths and anchors.
Registered current indexes label links to these pages with `<!-- docs-history -->` in a previous-links section.
Maintainers review semantic equivalence, implementation status and validation evidence.

## Japanese and public writing conventions

Before writing Japanese, reread the [writing style rules](https://raw.githubusercontent.com/megmogmog1965/claude-code-writing-style/main/plugins/writing-style/skills/style-review/references/rules.md), [Japanese technical writing rules](https://gist.githubusercontent.com/k16shikano/fd287c3133457c4fd8f5601d34aa817d/raw), and only the section identifying unnecessary prose (駄文の見分け方) in the [rhythm rules](https://gist.githubusercontent.com/k16shikano/eb2929f13ed19c97188393d297be8432/raw).
The project's ASCII parentheses and colon convention takes precedence over conflicting advice.
Use polite Japanese, one sentence per line, explicit subjects and headings that identify the topic.
Avoid fragments, vague demonstratives, personification, literal translations and colloquial wording; state unverified claims explicitly.
List labels are nouns followed by ASCII colons.
For terms without an established Japanese equivalent, choose meaningful words or explain the concrete behavior.
Prefer separate sentences to parenthetical asides in READMEs.
README, SECURITY.md and tool output use English as the primary language; paired documents retain the same information.
