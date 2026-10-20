//! Build script. It tells Cargo to build the crate again when a rules file changes.

fn main() {
    // The program holds a copy of the rules files. A change in the folder
    // (a new file or a changed file) must make Cargo build the crate again.
    println!("cargo:rerun-if-changed=../../rules");
}
