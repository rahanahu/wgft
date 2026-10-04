#!/usr/bin/env python3
"""Check repository Markdown links, declared pairs, and maintained navigation.

This is a deliberately small Markdown checker, not a renderer. It supports inline
and reference links, ATX/setext headings, GitHub duplicate slugs and HTML id/name
anchors. Fences, inline code and comments do not contain links. It never fetches
URLs; fragments in non-Markdown assets are outside its scope.
"""
import argparse
import html
import json
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

GENERATED = {'docs/cli.md'}
PAIR = re.compile(r'^\s*<!--\s*docs-pair:\s*(\S+)\s*-->\s*$', re.MULTILINE)
STATUS = re.compile(r'^\s*<!--\s*docs-status:\s*(historical|deprecated)\s*-->\s*$', re.MULTILINE)


def visible_lines(source):
    """Preserve line numbers while removing fenced code and HTML comments."""
    comment = False
    fence = None
    for line in source.splitlines():
        if fence:
            if re.match(r'^\s{0,3}' + re.escape(fence[0]) + '{' + str(fence[1]) + r',}\s*$', line):
                fence = None
            yield ''
            continue
        opening = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if opening:
            fence = (opening[1][0], len(opening[1]))
            yield ''
            continue
        out = ''
        while line:
            if comment:
                end = line.find('-->')
                if end < 0:
                    line = ''
                else:
                    line = line[end + 3:]
                    comment = False
            else:
                start = line.find('<!--')
                if start < 0:
                    out += line
                    line = ''
                else:
                    out += line[:start]
                    line = line[start + 4:]
                    comment = True
        yield out


def declarations(source, pattern):
    # Metadata is recognized only as a standalone comment outside code fences.
    fence = None
    result = []
    for line in source.splitlines():
        if fence:
            if re.match(r'^\s{0,3}' + re.escape(fence[0]) + '{' + str(fence[1]) + r',}\s*$', line):
                fence = None
            continue
        opening = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if opening:
            fence = (opening[1][0], len(opening[1]))
            continue
        result.extend(pattern.findall(line))
    return result


def slug(heading):
    heading = html.unescape(re.sub(r'<[^>]*>', '', heading)).lower()
    # GitHub keeps underscores and hyphens, Unicode letters, numbers and marks.
    heading = ''.join(c for c in heading if c in '_- ' or unicodedata.category(c)[0] in 'LNM')
    return heading.replace(' ', '-')


def anchors(source):
    found, used = set(), set()
    lines = list(visible_lines(source))
    for i, line in enumerate(lines):
        for anchor in re.finditer(r'<[^>]+\b(?:id|name)\s*=\s*[\"\']([^\"\']+)[\"\']', line):
            found.add(html.unescape(anchor[1]))
        heading = re.match(r'^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$', line)
        if heading:
            title = heading[1]
        elif i + 1 < len(lines) and line.strip() and re.match(r'^\s{0,3}(?:=+|-+)\s*$', lines[i + 1]):
            title = line.strip()
        else:
            continue
        base = slug(title)
        candidate, number = base, 0
        while candidate in used:
            number += 1
            candidate = f'{base}-{number}'
        used.add(candidate)
        found.add(candidate)
    return found


def destinations(source):
    """Yield (line number, destination); parentheses in destinations are balanced."""
    lines = list(visible_lines(source))
    refs = {}
    for number, line in enumerate(lines, 1):
        match = re.match(r'^\s{0,3}\[([^]]+)\]:\s*(<[^>]+>|\S+)', line)
        if match:
            refs[match[1].casefold()] = match[2].strip('<>')
    for number, line in enumerate(lines, 1):
        if re.match(r'^\s{0,3}\[[^]]+\]:', line):
            match = re.match(r'^\s{0,3}\[[^]]+\]:\s*(<[^>]+>|\S+)', line)
            if match:
                yield number, match[1].strip('<>')
            continue
        line = re.sub(r'(`+).*?\1', '', line)
        pattern = re.compile(r'(?:!?\[(?:\\.|[^]\n])*\])(?:\(|\[([^]\n]*)\])')
        for match in pattern.finditer(line):
            if match[1] is not None:
                key = match[1] or re.search(r'\[([^]]+)\]', match[0])[1]
                if key.casefold() in refs:
                    yield number, refs[key.casefold()]
                continue
            rest = line[match.end():].lstrip()
            if rest.startswith('<'):
                end = rest.find('>')
                if end >= 0:
                    yield number, rest[1:end]
                continue
            depth, end = 0, 0
            while end < len(rest):
                char = rest[end]
                if char == '\\' and end + 1 < len(rest):
                    end += 2
                    continue
                if char == '(':
                    depth += 1
                elif char == ')':
                    if depth == 0:
                        break
                    depth -= 1
                elif char.isspace() and depth == 0:
                    break
                end += 1
            if end:
                yield number, rest[:end]


def check(root, files, policy=None):
    policy = policy or {}
    errors = []
    contents = {p: (root / p).read_text(encoding='utf-8') for p in files if p.endswith('.md') and (root / p).is_file()}
    indexed = set(policy.get('current_indexes', []))
    for path, source in contents.items():
        if path in GENERATED:
            continue
        for number, destination in destinations(source):
            url = urlsplit(html.unescape(destination))
            if url.scheme or url.netloc or url.path.startswith('/'):
                continue
            target = (root / path).parent / unquote(url.path) if url.path else root / path
            target = target.resolve()
            try:
                rel = target.relative_to(root.resolve()).as_posix()
            except ValueError:
                errors.append(f'{path}:{number}: link escapes repository: {destination}')
                continue
            if not target.exists():
                errors.append(f'{path}:{number}: missing target: {destination}')
                continue
            if target.is_file() and rel.endswith('.md') and rel not in contents:
                errors.append(f'{path}:{number}: Markdown target is not tracked: {destination}')
            if url.fragment and rel in contents and unquote(url.fragment) not in anchors(contents[rel]):
                errors.append(f'{path}:{number}: missing fragment: {destination}')
            if path in indexed and rel in contents and (declarations(contents[rel], STATUS) or '/history/' in '/' + rel):
                original = source.splitlines()[number - 1]
                if '<!-- docs-history -->' not in original:
                    errors.append(f'{path}:{number}: historical/deprecated link needs docs-history label: {destination}')
        pairs = declarations(source, PAIR)
        if len(pairs) > 1:
            errors.append(f'{path}: multiple docs-pair declarations')
        for pair in pairs:
            other = ((root / path).parent / pair).resolve()
            try:
                other_rel = other.relative_to(root.resolve()).as_posix()
            except ValueError:
                errors.append(f'{path}: docs-pair escapes repository: {pair}')
                continue
            if other_rel not in contents:
                errors.append(f'{path}: missing docs-pair: {pair}')
            elif not any(((other.parent / reciprocal).resolve() == (root / path).resolve()) for reciprocal in declarations(contents[other_rel], PAIR)):
                errors.append(f'{path}: docs-pair is not reciprocal: {pair}')
    # The .ja.md convention declares a pair without per-page metadata boilerplate.
    for japanese in (p for p in contents if p.endswith('.ja.md')):
        english = japanese[:-6] + '.md'
        if english not in contents:
            errors.append(f'{japanese}: missing English language pair: {english}')
            continue
        for path, other in ((japanese, english), (english, japanese)):
            declared = any(((root / path).parent / p).resolve() == (root / other).resolve() for p in declarations(contents[path], PAIR))
            linked = any(((root / path).parent / unquote(urlsplit(dest).path)).resolve() == (root / other).resolve() for _, dest in destinations(contents[path]) if not urlsplit(dest).scheme)
            if not declared and not linked:
                errors.append(f'{path}: missing reciprocal language link to {other}')
    for stub, expected in policy.get('legacy_stubs', {}).items():
        if stub not in contents:
            errors.append(f'{stub}: registered legacy stub is missing')
            continue
        if 'deprecated' not in declarations(contents[stub], STATUS):
            errors.append(f'{stub}: legacy stub must declare deprecated status')
        for anchor in expected:
            if anchor not in anchors(contents[stub]):
                errors.append(f'{stub}: missing registered legacy anchor: {anchor}')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=args.root).decode().split('\0')
    policy_path = args.root / 'scripts/check-docs-policy.json'
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else {}
    errors = check(args.root, files, policy)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Documentation links, pairs and navigation checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
