//! v2 移行中の wgft の置き場。ワークスペースがビルドできることだけを示す。

fn main() {
    println!("wgft {}", wgft::VERSION);
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert_ne!(wgft::VERSION, "");
    }
}
