package main

import "testing"

func TestRustJapaneseLiterals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"comment only", "// 日本語のコメント\n/* 日本語 /* 入れ子 */ */\nfn main() {}\n", 0},
		{"plain english", "fn f() { println!(\"hello\"); }\n", 0},
		{"japanese string", "fn f() { println!(\"日本語\"); }\n", 1},
		{"escaped quote", "fn f() { let _ = \"a\\\"日\"; }\n", 1},
		{"raw string", "fn f() { let _ = r#\"日本 \"x\" \"#; }\n", 1},
		{"lifetime then string", "fn f<'a>(x: &'a str) { let _ = \"ok\"; }\n", 0},
		{"char literal", "fn f() { let _ = '日'; }\n", 1},
		{"cfg test module", "fn f() {}\n#[cfg(test)]\nmod t { fn g() { let _ = \"日本語\"; } }\n", 0},
		{"cfg test mid-file item then production", "#[cfg(test)]\nfn helper() { let _ = \"日本語\"; }\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test use then production", "#[cfg(test)]\nuse a::b;\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test mod semicolon", "#[cfg(test)]\nmod tests;\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test in comment", "// #[cfg(test)]\n/// #[cfg(test)]\n/* #[cfg(test)] */\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test in string", "fn f() { let _ = \"#[cfg(test)]\"; }\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test struct field", "struct S { #[cfg(test)] hook: u8, b: u8 }\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test last struct field", "struct S { b: u8, #[cfg(test)] hook: u8 }\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test enum variant", "enum E { #[cfg(test)] T, U }\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"cfg test fn parameter", "fn g(#[cfg(test)] a: u8) { eprintln!(\"日本語\"); }\n", 1},
		{"cfg test generic fn", "#[cfg(test)]\nfn f<A, B>() { let _ = \"日本語\"; }\nfn prod() { let _ = \"日本語\"; }\n", 1},
		{"escaped quote char", "fn f() { let _ = ('\\'', ','); let _ = \"日本語\"; }\n", 1},
		{"c raw string", "fn f() { let _ = cr#\"日本\"#; }\n", 1},
		{"c string", "fn f() { let _ = c\"日本\"; }\n", 1},
		{"byte raw string", "fn f() { let _ = br\"日本\"; }\n", 1},
	}
	for _, tc := range cases {
		if got := len(rustJapaneseLiterals("x.rs", tc.src)); got != tc.want {
			t.Errorf("%s: got %d hits, want %d", tc.name, got, tc.want)
		}
	}
}

func TestRustExempt(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]bool{
		"crates/wgft/tests/it.rs":      true,
		"crates/wgft/benches/b.rs":     true,
		`crates\wgft\tests\it.rs`:      true,
		"crates/wgft/src/main.rs":      false,
		"crates/wgft/src/tests/mod.rs": false,
	} {
		if got := rustExempt(path); got != want {
			t.Errorf("rustExempt(%q) = %v, want %v", path, got, want)
		}
	}
}
