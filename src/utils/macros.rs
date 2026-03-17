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
macro_rules! tprintln {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        if let Some(end) = msg.find(']') {
            println!("\x1b[36m{}\x1b[0m{}", &msg[..=end], &msg[end+1..]);
        } else {
            println!("{}", msg);
        }
    };
}
