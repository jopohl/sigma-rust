#[derive(Debug, PartialEq)]
pub(crate) enum WildcardToken {
    Star,
    QuestionMark,
    Pattern(Vec<char>),
}

/// Tokenize a string into a list of WildcardTokens
/// This method also takes care of converting escape sequences (backslashes) into the actual characters
/// See: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escaping
/// Therefore, it is crucial to use this method on a raw string provided in the Sigma rule
pub(crate) fn tokenize(s: &str) -> Vec<WildcardToken> {
    let mut result = vec![];
    let mut buffer: Vec<char> = vec![];

    let mut escape_mode = false;

    for (i, char) in s.chars().enumerate() {
        match char {
            '*' => {
                if escape_mode {
                    buffer.push(char);
                    escape_mode = false;
                    continue;
                }

                if !buffer.is_empty() {
                    result.push(WildcardToken::Pattern(buffer.clone()));
                    buffer.clear();
                }
                if let Some(WildcardToken::Star) = result.last() {
                    // Ignore multiple consecutive stars
                } else {
                    result.push(WildcardToken::Star)
                }
            }
            '?' => {
                if escape_mode {
                    buffer.push(char);
                    escape_mode = false;
                    continue;
                }

                if !buffer.is_empty() {
                    result.push(WildcardToken::Pattern(buffer.clone()));
                    buffer.clear();
                }

                result.push(WildcardToken::QuestionMark)
            }
            '\\' => {
                if !escape_mode {
                    escape_mode = true;
                } else {
                    buffer.push(char);
                    escape_mode = false;
                }
            }
            _ => {
                if escape_mode {
                    buffer.push('\\');
                    escape_mode = false;
                }
                buffer.push(char)
            }
        }
    }
    if escape_mode {
        buffer.push('\\');
    }
    if !buffer.is_empty() {
        result.push(WildcardToken::Pattern(buffer));
    }

    result
}

pub(crate) fn match_tokenized(tokens: &[WildcardToken], haystack: &str) -> bool {
    let mut pos = 0;
    let haystack_chars: Vec<char> = haystack.chars().collect();
    let mut starmode = false;

    'outer: for (i, token) in tokens.iter().enumerate() {
        let is_last_token = i == tokens.len() - 1;
        match token {
            WildcardToken::QuestionMark => {
                if pos >= haystack_chars.len() {
                    return false;
                }
                pos += 1;
            }
            WildcardToken::Pattern(p) => {
                if p.len() + pos > haystack_chars.len() {
                    return false;
                }
                if starmode {
                    starmode = false;
                    for j in 0..1 + haystack_chars.len() - p.len() - pos {
                        // Loop till a match is found
                        // If we process the last token, make sure we loop till the end of the haystack
                        if haystack_chars[pos + j..pos + j + p.len()].eq(p)
                            && (!is_last_token || pos + j + p.len() == haystack_chars.len())
                        {
                            pos += j + p.len();
                            continue 'outer;
                        }
                    }
                    return false;
                } else {
                    if !haystack_chars[pos..pos + p.len()].eq(p) {
                        return false;
                    }
                    pos += p.len();
                }
            }
            WildcardToken::Star => {
                if is_last_token {
                    return true;
                }
                starmode = true;
            }
        }
    }

    pos == haystack_chars.len()
}

pub(crate) fn wildcard_match(pattern: &str, haystack: &str) -> bool {
    let tokens = tokenize(pattern);
    match_tokenized(&tokens, haystack)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        assert_eq!(tokenize(""), vec![]);
        assert_eq!(
            tokenize("a*b"),
            vec![
                WildcardToken::Pattern(vec!['a']),
                WildcardToken::Star,
                WildcardToken::Pattern(vec!['b']),
            ]
        );
        assert_eq!(
            tokenize("a?b"),
            vec![
                WildcardToken::Pattern(vec!['a']),
                WildcardToken::QuestionMark,
                WildcardToken::Pattern(vec!['b']),
            ]
        );
        assert_eq!(
            tokenize("a\\*b"),
            vec![WildcardToken::Pattern(vec!['a', '*', 'b'])]
        );
        assert_eq!(
            tokenize("a\\?b"),
            vec![WildcardToken::Pattern(vec!['a', '?', 'b']),]
        );
        assert_eq!(
            tokenize("a\\b"),
            vec![WildcardToken::Pattern(vec!['a', '\\', 'b']),]
        );

        //https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escaping
        assert_eq!(
            tokenize(r"a\b"),
            vec![WildcardToken::Pattern(vec!['a', '\\', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\b"),
            vec![WildcardToken::Pattern(vec!['a', '\\', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\\b"),
            vec![WildcardToken::Pattern(vec!['a', '\\', '\\', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\\*b"),
            vec![WildcardToken::Pattern(vec!['a', '\\', '*', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\\\b"),
            vec![WildcardToken::Pattern(vec!['a', '\\', '\\', 'b']),]
        );

        assert_eq!(
            tokenize(r"hello***?world"),
            vec![
                WildcardToken::Pattern("hello".chars().collect()),
                WildcardToken::Star,
                WildcardToken::QuestionMark,
                WildcardToken::Pattern("world".chars().collect()),
            ]
        );
    }

    // TODO: Reorder those tests

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("ab", "ab"));
        assert!(!wildcard_match("ab", "ac"));
        assert!(!wildcard_match("ab", "abc"));
        assert!(!wildcard_match("abc", "ab"));
        assert!(wildcard_match("a\\*b", "a*b"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(wildcard_match("a?c", "a🔥c"));
        assert!(!wildcard_match("a?c", "a🔥🔥c"));
        assert!(!wildcard_match("a??c", "abc"));
        assert!(!wildcard_match("a?c?", "abc"));
        assert!(wildcard_match("ab?", "abc"));
        assert!(!wildcard_match("ab?", "abcd"));
        assert!(wildcard_match("a*", "a"));
        assert!(wildcard_match("a*", "acb"));
        assert!(wildcard_match("a*b", "ab"));
        assert!(!wildcard_match("a*?b", "ab"));
        assert!(wildcard_match("a*?b", "acb"));
        assert!(wildcard_match("a*b", "ads🔥🔥fggb"));
        assert!(wildcard_match("foo*bar", "foobar"));
        assert!(wildcard_match("foo*bar", "foobarbar"));
        assert!(wildcard_match("foo*bar*fizz", "foobarbarfizzfizz"));
        assert!(!wildcard_match("foo*bar*fizz", "foobarbarfizznope"));
        assert!(wildcard_match(r"hello\*??world", "hello*myworld"));
        assert!(wildcard_match(
            r"C:\\*\\*.exe",
            r"C:\Windows\System32\calc.exe"
        ));
        assert!(!wildcard_match(r"C:\\*\\*.exe", r"C:\test.exe"));
    }
}
