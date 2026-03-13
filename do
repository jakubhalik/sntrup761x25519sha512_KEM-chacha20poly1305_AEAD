write sntrup761x25519-sha512 in rust, write no comments in code, do not use single letter vars, instead of v, use val, instead if i use item, instead of c use char, when running any func let's have a dprintln! with some debugging info via macro_rules! dprintln {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!($($arg)*);
        }
    };
}
