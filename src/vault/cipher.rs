use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use argon2;

pub fn rand_key() -> Vec<u8> {
    let key = Aes256Gcm::generate_key().expect("failed to generate aes key");
    key.to_vec()
}

pub fn encrypt(k: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce = Aes256Gcm::generate_nonce().expect("failed to generate nonce");
    let cipher = Aes256Gcm::new_from_slice(k).unwrap();
    let ciphered_data = cipher
        .encrypt(&nonce, plaintext)
        .expect("failed to encrypt");
    // combining nonce and encrypted data together
    // for storage purpose
    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphered_data);
    encrypted_data
}
pub fn decrypt(k: &[u8], encrypted_data: &[u8]) -> Vec<u8> {
    let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
    let nonce = Nonce::try_from(nonce_arr).expect("failed to parse nonce");
    let cipher = Aes256Gcm::new_from_slice(k).unwrap();
    let plaintext = cipher
        .decrypt(&nonce, ciphered_data)
        .expect("failed to decrypt data, almost because you input password was wrong");
    plaintext
}

pub fn derive_key(master_password: &str, salt: &[u8]) -> Vec<u8> {
    // use hmac::Hmac;
    // use sha2::Sha256;

    //let rounds = 1_000_000;
    //let key = [0_u8; 32];
    //   pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, rounds, &mut key) .expect("failed to generate data key");

    let argon2 = argon2::Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut key)
        .expect("failed to generate data key");
    key.to_vec()
}

#[cfg(test)]
mod tests {
    use crate::vault::cipher::derive_key;

    #[test]
    fn df_time() {
        derive_key("my-password", b"salt-3434223403240");
        assert_eq!(2 + 2, 4);
    }
}
