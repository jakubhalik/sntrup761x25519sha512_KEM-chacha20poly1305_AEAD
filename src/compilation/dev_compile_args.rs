#[cfg(feature = "e2e-tests")]
use crate::compilation::e2e_registry;

fn handle_e2e(_args: &[String]) {
    #[cfg(not(feature = "e2e-tests"))]
    {
        eprintln!("Error: e2e tests not enabled");
        eprintln!("Rebuild with: cargo build --features e2e-tests");
        std::process::exit(1);
    }
    #[cfg(feature = "e2e-tests")]
    {
        if args.len() < 3 {
            eprintln!("Usage: {} --e2etest <test_name>", args[0]);
            eprintln!();
            list_e2e_tests();
            std::process::exit(1);
        }
        let test_name = &args[2];
        if test_name == "list" {
            list_e2e_tests();
            return;
        }
        match e2e_registry::find_test(test_name) {
            Some(test_fn) => test_fn(),
            None => {
                eprintln!("Unknown e2e test: '{}'", test_name);
                eprintln!();
                list_e2e_tests();
                std::process::exit(1);
            }
        }
    }
}

#[cfg(feature = "e2e-tests")]
fn list_e2e_tests() {
    let tests = e2e_registry::all_tests();
    if tests.is_empty() {
        eprintln!("No e2e tests registered");
    } else {
        eprintln!("Available e2e tests:");
        for (name, _) in tests {
            eprintln!("  {}", name);
        }
    }
}

fn print_help() {
    let bin = std::env::args().next().unwrap_or_else(|| "bin".to_string());
    println!("Usage: {}", bin);
    println!();
    println!("Options:");
    println!("  --e2etest <name>    Run an end-to-end test (requires --features e2e-tests)");
    println!("  --e2etest list      List available e2e tests");
    println!("  --help, -h          Show this help");
}

pub fn handle_args() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return false;
    }
    match args[1].as_str() {
        "--e2etest" => {
            handle_e2e(&args);
            true
        }
        "--help" | "-h" => {
            print_help();
            true
        }
        _ => false,
    }
}

