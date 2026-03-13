macro_rules! dprintln {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!($($arg)*);
        }
    };
}
