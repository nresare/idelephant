use rand::random;

// According to the spec(1) this needs to be at least 16 bytes. We go with 18
// as we will base64 encode the value and lengths not evenly divisible by 3 will
// have padding.
// 1) https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
const CHALLENGE_BYTE_COUNT: usize = 18;
pub fn make_token() -> Vec<u8> {
    random::<[u8; CHALLENGE_BYTE_COUNT]>().into()
}
