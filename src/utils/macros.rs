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
            $(pub $name: (&'static [&'static str],),)*
        }
        impl Args {
            fn new() -> Self {
                Args {
                    $($name: ($aliases),)*
                }
            }
            fn arg_map(&self) -> Vec<(&'static str, &'static [&'static str])> {
                vec![
                    $((stringify!($name), self.$name),)*
                ]
            }
        }
    };
}

