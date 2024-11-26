#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    #[error("The field modifiers '{0}' and '{1}' are conflicting")]
    ConflictingModifiers(String, String),

    #[error("Unknown field modifier '{0}' provided")]
    UnknownModifier(String),

    #[error("UTF16 encoding requested but no value transformation modifier provided (base64 or base64offset)"
    )]
    Utf16WithoutBase64,

    #[error(
        "The modifier '{0}' is ambiguous and therefore unsupported; use utf16le or utf16be instead"
    )]
    AmbiguousUtf16Modifier(String),

    #[error("No values provided for field '{0}'")]
    EmptyValues(String),

    #[error("Failed to parse regular expression: '{0}'")]
    RegexParsing(regex::Error),

    #[error(
        "The modifier '{0}' must not be combined with other modifiers except 'all' and 'fieldref'"
    )]
    StandaloneViolation(String),

    #[error("Failed to parse IP address '{0}': '{1}'")]
    IPParsing(String, String),

    #[error("Provided YAML is not a valid field representation: '{0}'")]
    InvalidYAML(String),

    #[error("Missing closing parenthesis in condition")]
    MissingClosingParenthesis(),

    #[error("Encountered unexpected token '{0}' in condition")]
    UnexpectedToken(String),

    #[error("Encountered invalid operator '{0}' in condition")]
    InvalidOperator(String),

    #[error("Condition references undefined identifiers: '{0:?}'")]
    UndefinedIdentifiers(Vec<String>),

    #[error("Selection '{0}' has an error: '{1}'")]
    SelectionParsingError(String, SelectionError),

    #[error("Field names must be string, got: '{0}'")]
    InvalidFieldName(String),

    #[error("The modifiers contains, startswith and endswith must be used with string values, got: '{0}'"
    )]
    InvalidValueForStringModifier(String),
}

#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    #[error("Selection without fields detected")]
    SelectionContainsNoFields(),

    #[error("Mixing keyword selection and field lists is not supported")]
    MixedKeywordAndFieldlist(),

    #[error("Selection has invalid type; it must be a list or dictionary")]
    InvalidSelectionType(),

    #[error("Invalid keyword selection, keywords must be string, number or boolean, got: '{0}'")]
    InvalidKeywordSelection(String),
}

#[cfg(feature = "serde_json")]
#[derive(Debug, thiserror::Error)]
pub enum JSONError {
    #[error("{0} is not a valid field value")]
    InvalidFieldValue(String),

    #[error("Events must be plain key value mappings")]
    InvalidEvent(),
}
