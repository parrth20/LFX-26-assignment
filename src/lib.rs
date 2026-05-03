use std::collections::TryReserveError;
use std::fmt;

use generic_ec::{Curve, Point, SecretScalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidCiphertext,
    AllocationFailed,
}

impl From<TryReserveError> for Error {
    fn from(_: TryReserveError) -> Self {
        Self::AllocationFailed
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCiphertext => f.write_str("invalid ciphertext"),
            Self::AllocationFailed => f.write_str("allocation failed"),
        }
    }
}

impl std::error::Error for Error {}

pub fn encrypt<E, R>(pk: &Point<E>, message: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
where
    E: Curve,
    R: RngCore + CryptoRng,
{
    let eph = SecretScalar::<E>::random(rng);
    let r = Point::<E>::generator() * &eph;
    let shared = pk * &eph;
    let r_bytes = r.to_bytes(true);
    let r_bytes = r_bytes.as_bytes();
    let out_len = r_bytes
        .len()
        .checked_add(message.len())
        .ok_or(Error::AllocationFailed)?;

    let mut out = Vec::new();
    out.try_reserve_exact(out_len)?;
    out.extend_from_slice(r_bytes);
    extend_xor_with_keystream(&mut out, &shared, message);
    Ok(out)
}

pub fn decrypt<E>(sk: &SecretScalar<E>, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
where
    E: Curve,
{
    let point_len = Point::<E>::serialized_len(true);
    let r_bytes = ciphertext
        .get(..point_len)
        .ok_or(Error::InvalidCiphertext)?;
    let encrypted_message = ciphertext
        .get(point_len..)
        .ok_or(Error::InvalidCiphertext)?;

    let r = Point::<E>::from_bytes(r_bytes).map_err(|_| Error::InvalidCiphertext)?;
    let shared = r * sk;

    let mut message = Vec::new();
    message.try_reserve_exact(encrypted_message.len())?;
    extend_xor_with_keystream(&mut message, &shared, encrypted_message);
    Ok(message)
}

fn extend_xor_with_keystream<E>(out: &mut Vec<u8>, shared: &Point<E>, input: &[u8])
where
    E: Curve,
{
    let digest = Sha256::digest(shared.to_bytes(true));
    out.extend(
        input
            .iter()
            .zip(digest.iter().cycle())
            .map(|(byte, mask)| byte ^ mask),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_ec::{
        Scalar,
        curves::{Ed25519, Secp256k1, Secp384r1},
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const ZERO_32: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONES_128: &str = concat!(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    const FRENCH: &str = concat!(
        "4a652073756973206c61206d65722c20632765737420706f757271756f69206a",
        "6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c",
        "206a6520766f757320646f6e6e65206c6120766965",
    );

    fn private_key<E: Curve>() -> SecretScalar<E> {
        let mut scalar = Scalar::<E>::from(65_537u64);
        SecretScalar::new(&mut scalar)
    }

    fn check_vector<E: Curve>(
        ciphertext_hex: &str,
        message_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ciphertext = hex::decode(ciphertext_hex)?;
        let expected_message = hex::decode(message_hex)?;
        let message = decrypt(&private_key::<E>(), &ciphertext)?;
        assert_eq!(message, expected_message);
        Ok(())
    }

    fn round_trip<E: Curve>() -> Result<(), Box<dyn std::error::Error>> {
        let sk = private_key::<E>();
        let pk = Point::<E>::generator() * &sk;
        let message = b"small original test message";
        let mut rng = ChaCha20Rng::from_seed([7; 32]);

        let ciphertext = encrypt(&pk, message, &mut rng)?;
        assert_eq!(
            ciphertext.len(),
            Point::<E>::serialized_len(true) + message.len()
        );
        assert_eq!(decrypt(&sk, &ciphertext)?, message);
        Ok(())
    }

    #[test]
    fn decrypts_ed25519_vectors() -> Result<(), Box<dyn std::error::Error>> {
        check_vector::<Ed25519>(
            concat!(
                "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b16",
                "021c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
            ),
            ZERO_32,
        )?;
        check_vector::<Ed25519>(
            concat!(
                "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e575",
                "cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
                "cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
                "cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
                "cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
            ),
            ONES_128,
        )?;
        check_vector::<Ed25519>(
            concat!(
                "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c",
                "6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde",
                "433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98",
                "067495fdb24b782dac9da5c0eb246c9fb15c00593e",
            ),
            FRENCH,
        )?;
        Ok(())
    }

    #[test]
    fn decrypts_secp256k1_vectors() -> Result<(), Box<dyn std::error::Error>> {
        check_vector::<Secp256k1>(
            concat!(
                "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad",
                "4940c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395",
                "f1",
            ),
            ZERO_32,
        )?;
        check_vector::<Secp256k1>(
            concat!(
                "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d0",
                "660ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b",
                "f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b",
                "f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b",
                "f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b",
                "f6",
            ),
            ONES_128,
        )?;
        check_vector::<Secp256k1>(
            concat!(
                "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd75879",
                "5f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661",
                "a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24",
                "e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
            ),
            FRENCH,
        )?;
        Ok(())
    }

    #[test]
    fn decrypts_secp384r1_vectors() -> Result<(), Box<dyn std::error::Error>> {
        check_vector::<Secp384r1>(
            concat!(
                "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497a",
                "fb8156b91c3f5baa12b4d81b5f44f2eb402399e501ed395e834c44d5c85008ef",
                "0a8b281240c5d409e4d1b85a586e493332",
            ),
            ZERO_32,
        )?;
        check_vector::<Secp384r1>(
            concat!(
                "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa",
                "5abb536caf174cc3258bf387f3e72e496c018163905de06e3a718c353cc3932c",
                "d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c",
                "d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c",
                "d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c",
                "d63e456eea56a0548bba4fe135f73faa9e",
            ),
            ONES_128,
        )?;
        check_vector::<Secp384r1>(
            concat!(
                "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a",
                "3e79b4895fe83593a0cbe39b4010d96c63d39a10133ef7f68aabfc63253f4537",
                "337539a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268",
                "337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b",
                "7f773eb58706",
            ),
            FRENCH,
        )?;
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        round_trip::<Ed25519>()?;
        round_trip::<Secp256k1>()?;
        round_trip::<Secp384r1>()?;
        Ok(())
    }

    #[test]
    fn rejects_short_ciphertext() {
        let result = decrypt(&private_key::<Secp256k1>(), &[]);
        assert_eq!(result, Err(Error::InvalidCiphertext));
    }
}
