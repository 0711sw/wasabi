//! Random ID generation with a safe alphabet.

/// Alphabet excluding vowels and ambiguous characters (I, O, U, A, E) to prevent
/// accidentally generating offensive or confusable strings.
const ID_ALPHABET: [char; 31] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L',
    'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z',
];

/// Generates a random ID of the specified length using a safe alphabet.
///
/// The alphabet excludes vowels to avoid generating offensive words,
/// and excludes ambiguous characters (I/1, O/0) for better readability.
pub fn generate_id(len: usize) -> String {
    nanoid::format(nanoid::rngs::default, &ID_ALPHABET, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_correct_length() {
        assert_eq!(generate_id(8).len(), 8);
        assert_eq!(generate_id(16).len(), 16);
    }

    #[test]
    fn contains_only_valid_characters() {
        let id = generate_id(100);
        assert!(id.chars().all(|c| ID_ALPHABET.contains(&c)));
    }

    #[test]
    fn contains_no_vowels() {
        let id = generate_id(1000);
        assert!(!id.contains(['A', 'E', 'I', 'O', 'U']));
    }
}
