//! What is built into a client: whom it trusts and where it starts.
//!
//! Read from the folder `trust/` when the crate is compiled. Every program
//! that needs them takes them from here: the bridge, its tools, the app.

/// The VLink root's key, 32 bytes as hex. Lists of bridges are checked
/// against it.
pub const ROOT_PUB: &str = include_str!("../../../trust/root.pub").trim_ascii();

/// Where a bridge reports in and a client asks for bridges.
pub const REGISTRIES: &[&str] = &entries::<{ count(REGISTRIES_TXT) }>(REGISTRIES_TXT);

/// Bridges to start from, before any list was fetched: a reference each,
/// `address:port#id`.
pub const SEEDS: &[&str] = &entries::<{ count(SEEDS_TXT) }>(SEEDS_TXT);

// A build with nothing built in would start nowhere and trust nobody.
const _: () = assert!(ROOT_PUB.len() == 64 && !REGISTRIES.is_empty() && !SEEDS.is_empty());

const REGISTRIES_TXT: &str = include_str!("../../../trust/registries.txt");
const SEEDS_TXT: &str = include_str!("../../../trust/seeds.txt");

// The two files hold one entry per line; a line that starts with `#` is a
// comment. They are taken apart by the compiler, so that what is built in
// is plain constants.

/// The first line of `text` without the space around it, and what follows it.
const fn first_line(text: &str) -> (&str, &str) {
    let bytes = text.as_bytes();
    let mut end = 0;
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    let (line, rest) = text.split_at(end);
    let rest = if rest.is_empty() { rest } else { rest.split_at(1).1 };
    (line.trim_ascii(), rest)
}

const fn is_entry(line: &str) -> bool {
    !line.is_empty() && line.as_bytes()[0] != b'#'
}

const fn count(mut text: &str) -> usize {
    let mut found = 0;
    while !text.is_empty() {
        let (line, rest) = first_line(text);
        if is_entry(line) {
            found += 1;
        }
        text = rest;
    }
    found
}

/// The entries of `text`; `N` is their [`count`].
const fn entries<const N: usize>(mut text: &'static str) -> [&'static str; N] {
    let mut out = [""; N];
    let mut found = 0;
    while !text.is_empty() {
        let (line, rest) = first_line(text);
        if is_entry(line) {
            out[found] = line;
            found += 1;
        }
        text = rest;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlink_proto::BridgeRef;

    #[test]
    fn what_is_built_in_is_well_formed() {
        assert_eq!(ROOT_PUB.len(), 64);
        assert!(ROOT_PUB.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!REGISTRIES.is_empty());
        assert!(REGISTRIES.iter().all(|r| r.starts_with("https://") && !r.ends_with('/')));
        assert!(!SEEDS.is_empty());
        for seed in SEEDS {
            seed.parse::<BridgeRef>().unwrap_or_else(|e| panic!("{seed}: {e}"));
        }
    }

    #[test]
    fn comments_and_blank_lines_are_not_entries() {
        const TEXT: &str = "# a comment\n\n  https://a.example/vlink  \r\n   # another\nhttps://b.example/vlink";
        assert_eq!(count(TEXT), 2);
        assert_eq!(entries::<2>(TEXT), ["https://a.example/vlink", "https://b.example/vlink"]);
        assert_eq!(count(""), 0);
        assert_eq!(count("# nothing but a comment\n\n"), 0);
    }
}
