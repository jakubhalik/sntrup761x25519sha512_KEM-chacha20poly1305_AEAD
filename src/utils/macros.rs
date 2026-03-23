#[macro_export]
macro_rules! dprintln {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!($($arg)*);
        }
    };
}
#[macro_export]
macro_rules! zeroize_all {
    ($($var:expr),+ $(,)?) => {{
        $($var.zeroize();)+
    }};
}

#[macro_export]
macro_rules! define_args_and_dispatchers {

    ($($name:ident: $aliases:expr),* $(,)?) => {

        pub struct Args {
            $(pub $name: &'static [&'static str],)*
        }

        impl Args {

            pub fn new() -> Self {
                Args {
                    $($name: $aliases,)*
                }
            }

            pub fn arg_map(&self) -> Vec<(&'static str, &'static [&'static str])> {
                vec![
                    $((stringify!($name), self.$name),)*
                ]
            }

            pub fn dispatch_client_traffic(
                &self,
                parsed_args: &[(String, Option<String>)],
                stream: &mut std::net::TcpStream,
                shared_secret: &[u8; 64],
            ) {
                for (key, value) in parsed_args {
                    match key.as_str() {
                        $(
                            stringify!($name) => {
                                if let Err(e) = crate::traffic::$name::client(
                                    stream,
                                    shared_secret,
                                    stringify!($name),
                                    value.as_deref().unwrap_or("")
                                ) {
                                    eprintln!(
                                        "[client][{}] failed: {}",
                                        stringify!($name),
                                        e
                                    );
                                }
                            }
                        )*
                        _ => {}
                    }
                }
            }

            pub fn dispatch_server_traffic(
                arg_name: &str,
                msg_bytes: &[u8],
            ) {
                match arg_name {
                    $(
                        stringify!($name) => {
                            if let Err(e) = 

                                crate::traffic::$name::server(
                                    msg_bytes
                                ) {

                                    eprintln!(
                                        "[server][{}] failed: {}", 
                                        stringify!($name), 
                                        e
                                    );

                                }
                        }
                    )*
                    other => {
                        eprintln!("[server][dispatch] unknown traffic arg: {}", other);
                    }
                }
            }

        }
    };
}

#[macro_export]
macro_rules! tprintln {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        let mut colored = String::new();
        let mut chars = msg.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_ascii_digit() {
                let mut num = String::from(c);
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_digit() {
                        num.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                let remaining: String = chars.clone().collect();
                if remaining.starts_with(" successes") {
                    colored.push_str(&format!("\x1b[32m{} successes\x1b[0m", num));
                    for _ in 0..10 { chars.next(); }
                } else if remaining.starts_with(" failures") {
                    colored.push_str(&format!("\x1b[31m{} failures\x1b[0m", num));
                    for _ in 0..9 { chars.next(); }
                } else {
                    colored.push_str(&num);
                }
            } else {
                colored.push(c);
            }
        }
        if let Some(end) = colored.find(']') {
            println!("\x1b[36m{}\x1b[0m{}", &colored[..=end], &colored[end+1..]);
        } else {
            println!("{}", colored);
        }
    };
}
