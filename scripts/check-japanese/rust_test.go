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
		{"after cfg test", "fn f() {}\n#[cfg(test)]\nmod t { fn g() { let _ = \"日本語\"; } }\n", 0},
	}
	for _, tc := range cases {
		if got := len(rustJapaneseLiterals("x.rs", tc.src)); got != tc.want {
			t.Errorf("%s: got %d hits, want %d", tc.name, got, tc.want)
		}
	}
}
