#[derive(Debug, PartialEq)]
pub enum WildcardToken {
    Star,
    QuestionMark,
    Pattern(Vec<char>),
}

/// Tokenize a string into a list of WildcardTokens
/// This method also takes care of converting escape sequences (backslashes) into the actual characters
/// See: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escaping
/// Therefore, it is crucial to use this method on a raw string provided in the Sigma rule
pub(crate) fn tokenize(s: &str, lowercase: bool) -> Vec<WildcardToken> {
    let mut result = vec![];
    let mut buffer: Vec<char> = vec![];

    let mut escape_mode = false;

    for char in s.chars() {
        match char {
            '*' => {
                if escape_mode {
                    buffer.push('*');
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
                    buffer.push('?');
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
                    buffer.push('\\');
                    escape_mode = false;
                }
            }
            _ => {
                if escape_mode {
                    buffer.push('\\');
                    escape_mode = false;
                }
                if lowercase {
                    buffer.extend(char.to_lowercase())
                } else {
                    buffer.push(char)
                }
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

macro_rules! match_tokens {
    ($haystack_iterator:expr, $tokens:expr) => {{
        let mut starmode = false;
        let mut haystack_iterator = $haystack_iterator.peekable();

        'outer: for (i, token) in $tokens.iter().enumerate() {
            let is_last_token = i == $tokens.len() - 1;
            match token {
                WildcardToken::QuestionMark => {
                    if haystack_iterator.next().is_none() {
                        return false;
                    }
                }
                WildcardToken::Pattern(p) if starmode => {
                    starmode = false;
                    let mut buffer: Vec<char> = vec![];

                    while let Some(haystack_char) = haystack_iterator.next() {
                        buffer.push(haystack_char);

                        if buffer.len() > p.len() {
                            buffer.remove(0);
                        }

                        // Loop till a match is found
                        // If we process the last token, make sure we loop till the end of the haystack
                        if buffer == *p && (!is_last_token || haystack_iterator.peek().is_none()) {
                            continue 'outer;
                        }
                    }
                    return false;
                }
                WildcardToken::Pattern(p) => {
                    for c in p {
                        if let Some(haystack_char) = haystack_iterator.next() {
                            if *c != haystack_char {
                                return false;
                            }
                        } else {
                            return false;
                        }
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

        haystack_iterator.peek().is_none()
    }};
}

pub(crate) fn match_tokenized(tokens: &[WildcardToken], haystack: &str, lowercase: bool) -> bool {
    if lowercase {
        match_tokens!(haystack.chars().flat_map(|c| c.to_lowercase()), tokens)
    } else {
        match_tokens!(haystack.chars(), tokens)
    }
}

// Function that only evaluates the star token, used for the detection wildcard matching for example selection*
pub(crate) fn starmatch(pattern: &str, haystack: &str) -> bool {
    let mut tokens: Vec<WildcardToken> = vec![];
    let mut buffer: Vec<char> = vec![];
    for c in pattern.chars() {
        if c == '*' {
            if !buffer.is_empty() {
                tokens.push(WildcardToken::Pattern(buffer.clone()));
                buffer.clear();
            }
            tokens.push(WildcardToken::Star);
        } else {
            buffer.push(c);
        }
    }
    if !buffer.is_empty() {
        tokens.push(WildcardToken::Pattern(buffer));
    }

    match_tokenized(&tokens, haystack, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn wildcard_match(pattern: &str, haystack: &str) -> bool {
        let tokens = tokenize(pattern, false);
        match_tokenized(&tokens, haystack, false)
    }

    #[test]
    fn test_tokenize() {
        assert_eq!(tokenize("", false), vec![]);
        assert_eq!(
            tokenize("a*b", false),
            vec![
                WildcardToken::Pattern(vec!['a']),
                WildcardToken::Star,
                WildcardToken::Pattern(vec!['b']),
            ]
        );
        assert_eq!(
            tokenize("A*B", false),
            vec![
                WildcardToken::Pattern(vec!['A']),
                WildcardToken::Star,
                WildcardToken::Pattern(vec!['B']),
            ]
        );
        assert_eq!(
            tokenize("A*B", true),
            vec![
                WildcardToken::Pattern(vec!['a']),
                WildcardToken::Star,
                WildcardToken::Pattern(vec!['b']),
            ]
        );
        assert_eq!(
            tokenize("a?b", false),
            vec![
                WildcardToken::Pattern(vec!['a']),
                WildcardToken::QuestionMark,
                WildcardToken::Pattern(vec!['b']),
            ]
        );
        assert_eq!(
            tokenize("a\\*b", false),
            vec![WildcardToken::Pattern(vec!['a', '*', 'b'])]
        );
        assert_eq!(
            tokenize("a\\?b", false),
            vec![WildcardToken::Pattern(vec!['a', '?', 'b']),]
        );
        assert_eq!(
            tokenize("a\\b", false),
            vec![WildcardToken::Pattern(vec!['a', '\\', 'b']),]
        );

        //https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escaping
        assert_eq!(
            tokenize(r"a\b", false),
            vec![WildcardToken::Pattern(vec!['a', '\\', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\b", false),
            vec![WildcardToken::Pattern(vec!['a', '\\', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\\b", false),
            vec![WildcardToken::Pattern(vec!['a', '\\', '\\', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\\*b", false),
            vec![WildcardToken::Pattern(vec!['a', '\\', '*', 'b']),]
        );
        assert_eq!(
            tokenize(r"a\\\\b", false),
            vec![WildcardToken::Pattern(vec!['a', '\\', '\\', 'b']),]
        );

        assert_eq!(
            tokenize(r"hello***?world", false),
            vec![
                WildcardToken::Pattern("hello".chars().collect()),
                WildcardToken::Star,
                WildcardToken::QuestionMark,
                WildcardToken::Pattern("world".chars().collect()),
            ]
        );
    }

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

    // Additional tests inspired by
    // https://github.com/cassaundra/wildflower/blob/main/tests/tests.rs

    #[test]
    fn test_simple_match() {
        assert!(wildcard_match("", ""));
        assert!(wildcard_match("a", "a"));
        assert!(wildcard_match("🔥", "🔥"));
        assert!(wildcard_match("abc", "abc"));

        assert!(!wildcard_match("a", ""));
        assert!(!wildcard_match("", "a"));
        assert!(!wildcard_match("abc", "xyz"));
        assert!(!wildcard_match("abc", "a"));
        assert!(!wildcard_match("abc", "ab"));
        assert!(!wildcard_match("abc", "abx"));
    }

    #[test]
    fn test_question_mark() {
        assert!(wildcard_match("?", "x"));
        assert!(wildcard_match("??", "xz"));
        assert!(wildcard_match("??", "🔥🔥"));
        assert!(wildcard_match("a?", "ab"));
        assert!(wildcard_match("hel???", "hello🔥"));
        assert!(wildcard_match("a?aa", "abaa"));
        assert!(wildcard_match("?a?a?", "baaax"));

        assert!(!wildcard_match("?", ""));
        assert!(!wildcard_match("?", "ab"));
        assert!(!wildcard_match("??", "a"));
        assert!(!wildcard_match("??", "🔥"));
        assert!(!wildcard_match("x?", "yx"));
        assert!(!wildcard_match("z?", "z"));
        assert!(!wildcard_match("abc???", "abcxy"));
        assert!(!wildcard_match("a?aa", "aaa"));
        assert!(!wildcard_match("?a?a?", "abcde"));
    }

    #[test]
    fn test_single_star() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "♡"));
        assert!(wildcard_match("*", "a"));
        assert!(wildcard_match("*", "abcdef"));
    }

    #[test]
    fn test_multiple_stars() {
        assert!(wildcard_match("***", ""));
        assert!(wildcard_match("***", "a"));
        assert!(wildcard_match("***", "abcdef"));
    }

    #[test]
    fn test_leading_star() {
        assert!(wildcard_match("*a", "a"));
        assert!(wildcard_match("*fast", "breakfast"));

        assert!(!wildcard_match("*a", "ab"));
        assert!(!wildcard_match("*fast", "break"));
    }

    #[test]
    fn test_trailing_star() {
        assert!(wildcard_match("a*", "a"));
        assert!(wildcard_match("break*", "breakfast"));
        assert!(wildcard_match("break\\**", "break*fast"));

        assert!(!wildcard_match("a*", "ba"));
        assert!(!wildcard_match("break*", "fast"));
        assert!(!wildcard_match("break\\**", "breakfast"));
    }

    #[test]
    fn test_inner_star() {
        assert!(wildcard_match("a*b", "ab"));
        assert!(wildcard_match("a*b", "aXb"));
        assert!(wildcard_match("a*b", "aXYZb"));

        assert!(!wildcard_match("a*b", "aX"));
        assert!(!wildcard_match("a*b", "Xb"));
    }

    #[test]
    fn test_mixed_stars() {
        assert!(wildcard_match("*a*b", "ab"));
        assert!(wildcard_match("*a*b", "Xab"));
        assert!(wildcard_match("*a*b", "aXb"));
        assert!(wildcard_match("*a*b", "XaYb"));

        assert!(!wildcard_match("*a*b", "a"));
        assert!(!wildcard_match("*a*b", "b"));

        assert!(wildcard_match("a*b*", "ab"));
        assert!(wildcard_match("a*b*", "abX"));
        assert!(wildcard_match("a*b*", "aXb"));
        assert!(wildcard_match("a*b*", "aXbY"));

        assert!(!wildcard_match("a*b*", "a"));
        assert!(!wildcard_match("a*b*", "b"));

        assert!(wildcard_match("*a*b*", "ab"));
        assert!(wildcard_match("*a*b*", "Xab"));
        assert!(wildcard_match("*a*b*", "aXb"));
        assert!(wildcard_match("*a*b*", "XaYb"));
        assert!(wildcard_match("*a*b*", "abX"));
        assert!(wildcard_match("*a*b*", "XabY"));
        assert!(wildcard_match("*a*b*", "XaYbZ"));

        assert!(!wildcard_match("*a*b*", "a"));
        assert!(!wildcard_match("*a*b*", "b"));

        assert!(wildcard_match("a*X*b", "aXb"));
        assert!(wildcard_match("a*X*b", "aYXb"));
        assert!(wildcard_match("a*X*b", "aXYb"));
        assert!(wildcard_match("a*X*b", "aYXYb"));

        assert!(!wildcard_match("a*X*b", "ab"));
        assert!(!wildcard_match("a*X*b", "aX"));
        assert!(!wildcard_match("a*X*b", "Yb"));
        assert!(!wildcard_match("a*X*b", "aYb"));
        assert!(!wildcard_match("a*X*b", "aZYZb"));
    }

    #[test]
    fn test_mixed_wildcards() {
        assert!(wildcard_match("?*", "h"));
        assert!(wildcard_match("?*", "hi!"));
        assert!(wildcard_match("h?ll*!", "hello world!"));
        assert!(wildcard_match("h?ll*!", "hollow!"));
        assert!(wildcard_match("h?ll*!", "hell!"));
        assert!(wildcard_match("??*", "ab"));
        assert!(wildcard_match("??*", "abc"));
        assert!(wildcard_match("??*", "abcd"));

        assert!(!wildcard_match("?*", ""));
        assert!(!wildcard_match("h?ll*!", "hllo world!"));
        assert!(!wildcard_match("h?ll*!", "hell"));
        assert!(!wildcard_match("??*", "a"));
    }

    #[test]
    fn test_escapes() {
        assert!(wildcard_match(r"\\", r"\"));
        assert!(wildcard_match(r"\\\\", r"\\"));
        assert!(wildcard_match(r"\?", r"?"));
        assert!(wildcard_match(r"\*", r"*"));
        assert!(wildcard_match(r"a\bc", r"a\bc"));
        assert!(wildcard_match(r"\?\*\a", "?*\\a"));
        assert!(wildcard_match(r"h?\?", "hi?"));
        assert!(wildcard_match(r"\??????", "? okay"));
        assert!(wildcard_match(r"\**", "*.*"));
    }

    #[test]
    fn test_whitespace() {
        assert!(wildcard_match("\n", "\n"));
        assert!(wildcard_match("?", "\n"));
        assert!(wildcard_match("\t*\n", "\t\t\n"));
        assert!(!wildcard_match(" ", "\n"));
        assert!(!wildcard_match(" ", "\t"));
    }

    #[test]
    fn test_extra() {
        assert!(!wildcard_match("??*?!?", "hello!"));
        assert!(!wildcard_match("hel*???!?**+", "hello!"));
        assert!(!wildcard_match("?*??ll*??*w\n", "hello!"));
        assert!(!wildcard_match("??*``*", r"``\ȣ?"));
    }
}
