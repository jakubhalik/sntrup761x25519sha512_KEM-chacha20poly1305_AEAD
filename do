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

3.
  There is not a rust lib for specifically doing sntrup761x25519_sha512 and that is ok, since there is a lib for sntrup761 and there is sha2 lib and x25519-dalek so please write me a mod.rs for using full sntrup761x25519_sha512 , never println! in it, but only dprintln! in it and use the macro #[macro_export]
  macro_rules! dprintln {
      ($debug:expr, $($arg:tt)*) => {
          if $debug {
              println!($($arg)*);
          }
      };
  }
   via use crate::dprintln;
  if a debug true bool is passed to it
    this is my main.rs right now :
#[path = "crypto/mod.rs"]
  mod crypto;

  mod utils;
  mod compilation;

  fn main() {
      if compilation::dev_compile_args::handle_args() {
          println!("compiled via dev compile args")
      } else {
          println!("nope")
      }
  } dont touch my dev_compile_args logic, that is about diff stuffs , u dont have to concern urself with that
  I will want u to extend that with a client and server mods that u will write which will both use the sntrup761x25519_sha512 to talk to each other, with a logic where if used with the arg <@portNum> to run as client otherwise to run as a tcp server, if u dont use @portNum u r expected to use portNum arg for deciding on which port will the tcp server run, but if u don't that's fine, it will just go to default 1024 or +1 if the port is taken, the terminal that is running the server should println!(someone sntrup761x25519_sha512 mated with me) and if the client println!(sntrup761x25519_sha512 mated with <port>), if ran with a debug flag use dprintln! for more details, for the runtime arg deciding logic use code like :

    const LOCALHOST: &str = "127.0.0.1";
    const IP: &str = LOCALHOST;
    const DEFAULT_PORT: u16 = 8080;

    let args: Vec<String> = env::args().collect();

    let mut port: u16 = args.iter()
        .find(|arg| arg.parse::<u16>().is_ok())
        .and_then(|arg| arg.parse().ok())
        .unwrap_or_else(|| {
            println!("No port provided, using {DEFAULT_PORT}");
            DEFAULT_PORT
        });
    let index_of_port: usize = args.iter()
        .position(|arg| arg == &port.to_string())
        .unwrap_or(usize::MAX);

    let debug_flags = [
        "-d", "-debug", "--debug", "-m", "-monitor", "--monitor"
    ];
    let debug: bool = args.iter().any(|arg| debug_flags.contains(&arg.as_str()));

    while TcpListener::bind((IP, port)).is_err() {
        println!("Port {} is taken, trying {}", port, port + 1);
        port += 1;
    }
from a diff program of mine

