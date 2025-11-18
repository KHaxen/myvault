use clap::{Parser, Subcommand,CommandFactory};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

#[derive(Parser, Debug)]
#[command(name = "myvault")]
#[command(about = "my kms", long_about = None)]
pub struct Arg {
    #[arg(short, long)]
    pub new: Option<String>,

    #[arg(short, long)]
    pub load: Option<String>,
}

#[derive(Parser, Debug)]
pub struct OpCli {
    #[arg(short, long)]
    pub index: Option<usize>,

    /// 命令
    #[command(subcommand)]
    pub op: Op,
}

#[derive(Subcommand, Debug)]
pub enum Op {
    /// 查看指定主题
    View {
        /// 打印所有的key名
        #[arg(short, long)]
        all: bool,
        /// 打印指定key name的password
        name: Option<String>,
    },
    /// 加新的主题
    New {
        /// 主题名
        title: String,
        /// 账户
        account: String,
        /// 密码
        master_key: String,
    },
    /// 增加额外的密码
    Extra {
        /// 其它密码的名字
        name: String,
        /// 密码
        password: String,
    },
    /// 改密
    Change {
        /// 是否改主密码
        #[arg(short, long)]
        master: bool,
        /// 改指定的其它密码
        #[arg(short, long)]
        key: Option<String>,
        /// 新密码
        new_password: String,
    },
}

pub fn get_password() -> Result<String, ReadlineError> {
    let mut rl = DefaultEditor::new()?;
    let pwd = rl.readline("password:  ");
    rl.clear_screen().unwrap();
    pwd
}
pub fn help() {
    let help_text = OpCli::command().render_help().to_string();
    let help = &help_text[14..];
    println!("please input command, format: {}", help);
    println!("input [COMMAND] -h to view option and argument");
}
pub fn get_command() -> Result<OpCli, ReadlineError> {
    let mut rl = DefaultEditor::new()?;
    //rl.clear_screen().unwrap();
    loop {
        let readline = rl.readline("command>> ");
        match readline {
            Ok(line) => {
                let args: Vec<&str> = line.split_whitespace().collect();
                let mut cmd = Vec::new();
                cmd.push("dummy");
                cmd.extend(args);

                match OpCli::try_parse_from(cmd) {
                    Ok(op) => return Ok(op),
                    Err(e) => {
                        println!("{}", e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    Err(ReadlineError::Interrupted)
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_subcommand() {
        let op = OpCli::new("").no_bin_name();
        assert_eq!(add(1, 2), 3);
    }

    #[test]
    fn test_no_app_name() {
        // This assert would fire and test will fail.
        // Please note, that private functions can be tested too!
        assert_eq!(bad_add(1, 2), 3);
    }
}
