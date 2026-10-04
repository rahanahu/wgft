# Documentation maintenance

[日本語](documentation.ja.md) · [Development documents](README.md)

## Sources and scope

Repository documents describe the branch being read.
Documents on `main` can include changes that are not in the latest release.
For a released version, read the same document at its tag and the release notes; do not infer availability from a merged design alone.

| Information | Canonical source |
|---|---|
| Supported behavior, constraints and compatibility | Current pages reached from the [design index](../design/README.md) |
| Installation and operation | Current pages reached from the [manual index](../manual/README.md) |
| Test gates and triggers | [Testing policy](testing.md) |
| Test execution and laboratory setup | [Lab instructions](../../lab/README.md) and the relevant script's header |
| Unimplemented tests and limits of verification | [Additional test catalog](testing-catalog.md) |
| Package responsibilities and execution paths | [Architecture](architecture.md) |
| Commit and release procedure | [Commits](commits.md) and [releases](releases.md) |
| Reasons for past decisions and measured results | Design history, development history and the relevant pull request |
| CLI help and examples | `cmd/wgft/helptext.go`, which generates [CLI reference](../cli.md) |

Read the repository entry rules first, then the index for the affected area and the pages covering the changed behavior.
Follow a history link when the rationale, old behavior or original measurement is needed.
Humans and coding agents use the same scoped discovery: a change to an installation procedure does not require reading every design record.
Check links to adjacent constraints before changing a decision that affects several areas.

## Adding or changing documents

1. Choose the canonical page by information type. Extend that page when it already owns the subject, and link to it from related pages instead of repeating policy.
2. For a changed decision, revise the current design before implementation. Keep drafts on the working branch, identify proposed or unimplemented behavior explicitly, and record the reason separately from the current contract.
3. Inspect the implementation and relevant tests before describing behavior as available. Publish operational commands as verified procedures only after they have run in the lab or on the target machine. State unverified platforms, missing implementation and other caveats explicitly.
4. Keep an English/Japanese pair's structure and information equivalent. Update both files in the same change, with natural wording in each language and reciprocal language links. A Japanese-only technical design body may remain single-language; bilingual indexes identify its language.
5. Update the appropriate index with an entry whose title and destination describe its role. Move completed plans out of current task navigation and into a history section. Preserve the reasoning needed to understand the current decision.
6. Preserve old paths and fragment links as deprecated navigation stubs or explicit anchors. Point to the new canonical section and state that the old page is deprecated. Register preserved stubs and anchors in `scripts/check-docs-policy.json`; removal needs an explicit decision about published links.
7. Run the documentation checks, inspect the rendered headings and links, and report which behavior was verified and which remains unverified. Apply the [test policy](testing.md) when the change includes scripts, test fixtures or workflow files.

A merged specification is a contract or a documented plan; merging does not prove that its implementation exists.
When a branch contains a design draft, name its implementation status and do not present that draft as the latest released behavior.
Historical wording such as "must be completed before v1" stays in a record with its original scope and provenance, rather than in current instructions.

## Update milestones

- Decision:Update the current specification and record the rationale, alternatives and unverified assumptions in history.
- Implementation:Check the code and tests, remove a pending label only for the implemented part, and update affected manuals, examples, indexes and verification caveats.
- Release:Check documents against the tagged implementation, identify changes since the latest release, update the README status and release notes, and recheck upgrade instructions and platform caveats.

For experiments, the revision record contains the result, its effect on design and remaining unknowns.
Detailed measurements, repetitions and timings belong in the pull request.
A completed plan is retained as history with a bounded title, status and source revision; its continued existence does not make it an active task.

## Generated reference and images

Do not edit `docs/cli.md` manually.
Edit the command help and regenerate it in the same commit:

```sh
go test ./cmd/wgft -run TestCLIDocUpToDate -update
```

`TestCLIDocUpToDate` checks agreement with the help and requires examples for executable commands.
Help describing behavior must be based on laboratory verification.
The READMEs link to the generated reference and `wgft <command> --help` instead of repeating a command table.

After changing Web UI templates, text or sample data, run `scripts/screenshot-ui.sh` and inspect the size of the image diff before committing.
The script's header defines its prerequisites and procedure.
Use Mermaid for README diagrams.

## Automated checks

```sh
python3 scripts/check-docs.py
python3 scripts/check-docs-test.py
bash scripts/check-ascii-punct.sh
```

`lint-output` runs these documentation checks for every push and pull request, including document-only changes; the weekly scheduled vulnerability check is separate.
The link checker reads tracked Markdown, checks relative file destinations and Markdown fragments, explicit HTML anchors, GitHub-style duplicate heading slugs and reference links.
It ignores fenced code, inline code and HTML comments, and never fetches external URLs.
Fragments in non-Markdown assets, rendered HTML links, and exotic Markdown extensions are outside its scope.
The generated CLI page is exempt from parsing because examples are checked by its generating Go test; links to its headings are still checked.

An English/Japanese pair is declared by `.ja.md` filenames or an optional reciprocal `<!-- docs-pair: other-file.md -->` comment.
The checker verifies existence and reciprocal language links or declarations, not translation quality or semantic equivalence.
Single-language design bodies and historical records need no pair declaration.
Use `<!-- docs-status: historical -->` on historical records and `<!-- docs-status: deprecated -->` on old navigation stubs.
The current indexes listed in the checker policy can link to such pages only on a line labeled `<!-- docs-history -->`; place that link in a clearly titled history or deprecated-links section.
The registry also detects deletion of retained legacy pages and anchors.
The check cannot establish whether implementation or validation is complete; maintainers review that evidence.

## Japanese and public writing conventions

Before writing Japanese documents, reread the [writing style rules](https://raw.githubusercontent.com/megmogmog1965/claude-code-writing-style/main/plugins/writing-style/skills/style-review/references/rules.md), [Japanese technical writing rules](https://gist.githubusercontent.com/k16shikano/fd287c3133457c4fd8f5601d34aa817d/raw), and only the section distinguishing useful pauses from unnecessary prose in the [rhythm rules](https://gist.githubusercontent.com/k16shikano/eb2929f13ed19c97188393d297be8432/raw).
The project's ASCII parentheses and colon convention takes precedence over conflicting punctuation advice.

Use polite Japanese, one sentence per line, definitions with an explicit subject, and headings that identify their subject.
Avoid sentence fragments, vague demonstratives, personification, literal translations and colloquial wording; mark unverified claims explicitly.
Use noun labels followed by ASCII colons in lists.
When a term has no established Japanese equivalent, choose words that carry its meaning or explain it concretely.
Prefer separate sentences to parenthetical asides in READMEs.
README, SECURITY.md and tool output use English as their primary language; paired documents retain the same information.
