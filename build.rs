use cc;

fn main() {
    cc::Build::new().file("src/ptrace.c").compile("ptrace");
}
