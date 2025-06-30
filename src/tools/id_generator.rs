const ID_ALPHABET: [char; 31] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L',
    'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z',
];

pub fn generate_id(len: usize) -> String {
    nanoid::format(nanoid::rngs::default, &ID_ALPHABET, len)
}
