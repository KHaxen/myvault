pub mod command;
mod vault;

use std::error::Error;

use clap::Parser;

use vault::cipher::{encrypt, decrypt};
use command::*;
use std::path::Path;
use vault::file::{save, load, Block,KV};

fn main() -> Result<(), Box<dyn Error>> {
    let args = Arg::parse();

    let password = get_password().expect("no password");
    if let Some(ref f) = args.new {
        return Ok(vault::file::new(Path::new(f), &password)?);
    }

    if let Some(ref f) = args.load {
        let (fh, mut blocks) = load(Path::new(f), &password).unwrap();
        let mut i = 1u32; // human：1-based
        for block in &blocks {
            println!("index: {}, title: {}", i, block.title);
            i = i + 1;
        }
        println!("this is all.\n");
        let file_key = vault::file::FILE_KEY.get().expect("file key not exists");
        help();

        loop {
            let op = get_command()?;

            let mut index = 0;
            if let Some(i) = op.index {
                if i > blocks.len() {
                    println!("invalid index");
                    continue;
                }
                index = i - 1; // program：0-based
            }
            match op.op {
                Op::View { all, name } => {
                    let block = blocks.get(index).unwrap();
                    if all {
                        let init = "".to_string();
                        let extra_keys = block.multi_key.iter().fold(init, |b, a| b + &a.key);
                        println!(
                            "title: {}, account: {}, extra keys: {}",
                            block.title, block.account, extra_keys
                        );
                    } else if let Some(k) = name {
                        let kv = block.multi_key.iter().find(|&kv| kv.key == k);
                        match kv {
                            Some(kv) => {
                                let pwd = decrypt(file_key, &kv.value);
                                println!(
                                    "title: {}, name:{}，password:{}",
                                    block.title,
                                    k,
                                    String::from_utf8(pwd).unwrap()
                                );
                            }
                            None => {
                                println!("title: {}, name:{}，not exists", block.title, k);
                            }
                        }
                    } else {
                        let pwd = decrypt(file_key, block.encrypted_pwd.as_slice());
                        println!(
                            "title: {}, account:{}，password:{}",
                            block.title,
                            block.account,
                            String::from_utf8(pwd).unwrap()
                        );
                    }
                }
                Op::New {
                    title,
                    account,
                    master_key,
                } => {
                    let encrypted_pwd = encrypt(file_key, master_key.as_bytes());
                    blocks.push(Block {
                        title: title.to_string(),
                        account,
                        encrypted_pwd,
                        multi_key: Vec::new(),
                    });
                    let r = save(Path::new(f), &fh, &blocks);
                    match r {
                        Err(e) => println!("error saving file: {}", e),
                        Ok(_) => {
                            println!("新目标保存成功: index: {}, title: {}", blocks.len(), title)
                        }
                    }
                }
                Op::Change {
                    master,
                    key,
                    new_password,
                } => {
                    if master {
                        blocks[index].encrypted_pwd = encrypt(file_key, new_password.as_bytes());
                    } else {
                        if key == None {
                            println!("not specify extra key");
                            continue;
                        }
                        let key = key.unwrap();
                        let block = blocks.get_mut(index).expect("no block");
                        let kv = block.multi_key.iter_mut().find(|kv| kv.key == key);
                        match kv {
                            Some(kv) => {
                                kv.value =
                                   encrypt(file_key, new_password.as_bytes());
                            }
                            None => {
                                println!(
                                    "title: {}, key:{}，not exists",
                                    blocks[index].title, key
                                );
                                continue;
                            }
                        }
                    }

                    let r = vault::file::save(Path::new(f), &fh, &blocks);
                    match r {
                        Err(e) => println!("error saving new password: {}", e),
                        Ok(_) => println!("new password 保存成功"),
                    }
                }
                Op::Extra {  name, password } => {
                    let block = blocks.get_mut(index).unwrap();
                    let kv = block.multi_key.iter().find(|kv| kv.key == name);
                    if kv.is_some()  {
                        println!("this extra key already exists");
                        continue;
                    }
                    let encrypted_pwd = encrypt(file_key, password.as_bytes());
                    block.multi_key.push(KV{key: name, value: encrypted_pwd});
                    let r = vault::file::save(Path::new(f), &fh, &blocks);
                    match r {
                        Err(e) => println!("error saving extra key: {}", e),
                        Ok(_) => println!("extra key 保存成功"),
                    }
                }
            }
        }
    }

    Ok(())
}
