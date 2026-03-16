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
