1. 
  write sntrup761x25519-sha512 in rust, write no comments in code, do not use single letter vars, instead of v, use val, instead if i use item, instead of c use char, when running any func let's have a dprintln! with some debugging info via macro_rules! dprintln {
      ($debug:expr, $($arg:tt)*) => {
          if $debug {
              println!($($arg)*);
          }
      };
  }

2.
  ] fd
  Cargo.toml
  LICENSE
  README.md
  crypto/
  crypto/post_quantum/
  crypto/post_quantum/sntrup761x25519-sha512/
  crypto/post_quantum/sntrup761x25519-sha512/latex_math_expl/
  crypto/post_quantum/sntrup761x25519-sha512/latex_math_expl/math.tex
  crypto/post_quantum/sntrup761x25519-sha512/latex_math_expl/math_short.tex
  crypto/post_quantum/sntrup761x25519-sha512/latex_math_expl/math_shortless.tex
  crypto/post_quantum/sntrup761x25519-sha512/main.rs
  do
  src/
  src/main.rs
  utils/
  utils/macros.rs
  version

  I want the current crypto/post_quantum/sntrup761x25519-sha512/main.rs to be more of a lib, file with functions impls etc to use in my project, keep the crypto in the one file as they are, but put tests of the lib file into a diff file and what is now the main func in the 
  crypto/post_quantum/sntrup761x25519-sha512/main.rs
  make into a 
  crypto/post_quantum/sntrup761x25519-sha512/e2e.rs
  and in the main root main.rs so far do not have much of anything, but have there to if compiled (cargo built or cargo ran) with flag --with-e2e-tests that running the bin then with --e2etest <the name of dir in which is a e2e.rs file will run that func there>

