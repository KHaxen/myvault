use super::cipher::*;
use std::path::PathBuf;

use std::time::*;

use postcard::{from_bytes, to_slice};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct FileHeader {
    magic: u32,
    ver: u32,
    create_time: SystemTime,
    modify_time: SystemTime,
    salt: Vec<u8>,
    env_key: Vec<u8>,
}

impl Display for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let tm: chrono::DateTime<chrono::Local>  =   self.create_time.into();
        write!(f,"magic: {}, ver: {}, create_time: {:#?}", String::from_utf8(self.magic.to_be_bytes().to_vec()).unwrap(), self.ver, tm.to_utc())
    }
}
pub static FILE_KEY: OnceLock<Vec<u8>> = OnceLock::new();
const FHLEN: usize = 256;

impl FileHeader {
    pub fn new(pwd: &str) -> FileHeader {
        let rk = rand_key();
        let salt = rand_key();
        let dk = derive_key(pwd, salt.as_slice());

        let value = FILE_KEY.get_or_init(|| rk.clone());
        FileHeader {
            magic: 0x4D595654, // MYVT
            ver: 0x01,
            create_time: SystemTime::now(),
            modify_time: SystemTime::now(),
            salt,
            env_key: encrypt(dk.as_slice(), value.as_slice()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct KV {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Block {
    pub title: String,
    pub account: String,
    pub encrypted_pwd: Vec<u8>,
    pub multi_key: Vec<KV>,
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let pwd =  String::from_utf8(decrypt(FILE_KEY.get().expect("file key"), &self.encrypted_pwd)).expect("decrypt env key");
        write!(f, "title: {}\naccount: {}\npassword: {}", self.title, self.account, pwd)
    }
}
// file physical struct
// ================================
//  FileHeader(256 byte)
// =================================
//  EncryptedData(all data)
// ==================================
//
// Decrypt(FILE_KEY, EncryptedData) = Vec<Block>
//

pub fn load(f: &Path, pwd: &str) -> Result<(FileHeader, Vec<Block>), Box<dyn Error>> {
    let data: Vec<u8> = fs::read(f)?;
    if data.len() < FHLEN {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "File too short to contain a valid header",
        )));
    }
    let fh: FileHeader = from_bytes(&data[0..FHLEN]).expect("decode header");
    let dk = derive_key(pwd, fh.salt.as_slice());

    FILE_KEY.get_or_init(|| decrypt(&dk, fh.env_key.as_slice()));

    println!("file info: {fh}");
    if data.len() == FHLEN {
        return Ok((fh, Vec::new()));
    }
    let encrypted_body = &data[FHLEN..];
    let decrypted_body = decrypt(FILE_KEY.get().expect("file key"), encrypted_body);
    let blocks: Vec<Block> = from_bytes(&decrypted_body).expect("load blocks");
    Ok((fh, blocks))
}

pub fn save(f: &Path, fh: &FileHeader, body: &Vec<Block>) -> Result<(), std::io::Error> {
    let mut tmp = PathBuf::from(f);
    tmp.set_extension("~");
    let _ = fs::copy(f, tmp.as_path()); // Ignore error if file doesn't exist

    let mut header_buf = [0u8; FHLEN];
    let _used_header = to_slice(&fh, &mut header_buf).unwrap();

    let serialized_body= postcard::to_vec::<_, { 1024*1024 }>(body).unwrap();
    let encrypted_body = encrypt(FILE_KEY.get().expect("file key"), &serialized_body);

    let mut file_content = Vec::new();
    file_content.extend_from_slice(&header_buf);
    file_content.extend_from_slice(&encrypted_body);

    fs::write(f, &file_content)
}

pub fn new(f: &Path, pwd: &str) -> Result<(), std::io::Error> {
    let fh = FileHeader::new(pwd);

    let mut buf = [0u8; 256];

    let _used = to_slice(&fh, &mut buf).unwrap();
    // assert_eq!(used, &[0x01]);
    fs::write(f, &buf[..])
}
