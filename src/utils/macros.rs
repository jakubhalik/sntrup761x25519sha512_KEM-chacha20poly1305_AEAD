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
macro_rules! define_args {
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
        }
    };
}

#[macro_export]
macro_rules! dispatch_client_traffic {
    ($args:expr, $stream:expr, $shared_secret:expr, {
        $($func_name:ident => $module:path),* $(,)?
    }) => {
        for (key, value) in $args.iter() {
            match key.as_str() {
                $(
                    stringify!($func_name) => {
                        use $module as _mod;
                        if let Err(e) = _mod::client(
                            $stream, 
                            $shared_secret, 
                            value.as_deref().unwrap_or("")
                        ) {
                            eprintln!(
                                "[{}] failed: {}",
                                stringify!($func_name), 
                                e
                            );
                        }
                    }
                )*
                other => {
                    eprintln!("[dispatch] unknown traffic arg: {}", other);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! dispatch_server_traffic {
    ($arg:expr, $message:expr, {
        $($func_name:ident => $module:path),* $(,)?
    }) => {
        match $arg {
            $(
                stringify!($func_name) => {
                    use $module as _mod;
                    if let Err(e) = _mod::server($message) {
                        eprintln!(
                            "[{}::server] failed: {}",
                            stringify!($func_name),
                            e
                        );
                    }
                }
            )*
            other => {
                eprintln!(
                    "[server traffic] unknown traffic arg: {}",
                    other
                );
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
