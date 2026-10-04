#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('check_docs', Path(__file__).with_name('check-docs.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class DocumentationChecks(unittest.TestCase):
    def run_check(self, files, policy=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            return checker.check(root, list(files), policy)

    def test_missing_target_and_fragment(self):
        errors = self.run_check({'a.md': '[file](missing.md)\n[fragment](b.md#absent)', 'b.md': '# Present'})
        self.assertEqual(len(errors), 2)
        self.assertIn('missing target', errors[0])
        self.assertIn('missing fragment', errors[1])

    def test_heading_anchors_and_fences(self):
        self.assertFalse(self.run_check({'a.md': '[explicit](b.md#old)\n[duplicate](b.md#same-1)\n[setext](b.md#setext)\n~~~\n[ignored](missing.md)\n~~~\n`[ignored](missing.md)`', 'b.md': '<a id="old"></a>\n# Same\n# Same\nSetext\n---\n```md\n# Ignored\n```'}))
        self.assertNotIn('ignored', checker.anchors('```\n# Ignored\n```'))

    def test_angle_paths_parentheses_external_and_reference_links(self):
        self.assertFalse(self.run_check({'a.md': '[space](<folder/a b.md#title>)\n[paren](a(b).md)\n[web](https://example.test/missing#fragment)\n[mail](mailto:a@example.test)\n[x][ref]\n[ref]: folder/a%20b.md#title', 'folder/a b.md': '# Title', 'a(b).md': '# Valid'}))

    def test_pair_missing_and_nonreciprocal(self):
        errors = self.run_check({'a.md': '<!-- docs-pair: a.ja.md -->'})
        self.assertIn('missing docs-pair', errors[0])
        errors = self.run_check({'a.md': '<!-- docs-pair: a.ja.md -->', 'a.ja.md': '# JA'})
        self.assertIn('not reciprocal', errors[0])
        self.assertFalse(self.run_check({'a.md': '<!-- docs-pair: a.ja.md -->', 'a.ja.md': '<!-- docs-pair: a.md -->'}))

    def test_filename_pairs_need_both_files_and_language_links(self):
        self.assertIn('missing English language pair', self.run_check({'guide.ja.md': '# Guide'})[0])
        self.assertIn('missing reciprocal language link', self.run_check({'guide.md': '# EN', 'guide.ja.md': '# JA'})[0])
        self.assertFalse(self.run_check({'guide.md': '[日本語](guide.ja.md)', 'guide.ja.md': '[English](guide.md)'}))

    def test_escaped_labels_images_and_inline_code_heading(self):
        self.assertFalse(self.run_check({'a.md': r'[escaped \] label](b.md#functionab)' + '\n![image](image.png)', 'b.md': '# `Function(a,b)`', 'image.png': 'fixture'}))
        self.assertIn('missing target', self.run_check({'a.md': '![image](missing.png)'})[0])

    def test_multiline_comments_and_marker_examples(self):
        self.assertFalse(self.run_check({'a.md': '<!--\n[ignored](missing.md)\n-->\nUse `<!-- docs-pair: other.md -->` as an example.'}))
        self.assertFalse(self.run_check({'README.md': '[current](guide.md)', 'guide.md': 'Use `<!-- docs-status: historical -->` as an example.'}, {'current_indexes': ['README.md']}))
        self.assertFalse(self.run_check({'README.md': '[current](guide.md)', 'guide.md': '```html\n<!-- docs-status: historical -->\n<!-- docs-pair: missing.md -->\n```'}, {'current_indexes': ['README.md']}))

    def test_deprecated_page_requires_registry_and_protects_original_anchors(self):
        files = {'old.md': '<!-- docs-status: deprecated -->\n# Original\n# Original\n<a id="published"></a>'}
        self.assertIn('deprecated page is not registered', self.run_check(files)[0])
        policy = {'legacy_stubs': {'old.md': ['original', 'original-1', 'published']}}
        self.assertFalse(self.run_check(files, policy))
        files['old.md'] = '<!-- docs-status: deprecated -->\n# Original'
        errors = self.run_check(files, policy)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all('missing registered legacy anchor' in error for error in errors))
        self.assertFalse(self.run_check({'current.md': '# Current', 'docs/cli.md': '# Generated'}))

    def test_legacy_registry_detects_deletion_and_anchor_loss(self):
        policy = {'legacy_stubs': {'old.md': ['old-anchor']}}
        self.assertIn('stub is missing', self.run_check({}, policy)[0])
        self.assertIn('missing registered legacy anchor', self.run_check({'old.md': '<!-- docs-status: deprecated -->'}, policy)[0])
        self.assertFalse(self.run_check({'old.md': '<!-- docs-status: deprecated -->\n<a id="old-anchor"></a>'}, policy))

    def test_current_index_history_and_generated_exemption(self):
        policy = {'current_indexes': ['README.md']}
        files = {'README.md': '[old](old.md)', 'old.md': '<!-- docs-status: historical -->', 'docs/cli.md': '[generated example](missing.md)'}
        self.assertIn('needs docs-history label', self.run_check(files, policy)[0])
        files['README.md'] += ' <!-- docs-history -->'
        self.assertFalse(self.run_check(files, policy))


if __name__ == '__main__':
    unittest.main()
