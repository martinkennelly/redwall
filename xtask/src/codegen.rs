use aya_gen::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("redwall-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr"];
    let bindings = aya_gen::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;

    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
