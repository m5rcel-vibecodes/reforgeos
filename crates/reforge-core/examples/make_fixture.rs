#[path = "../tests/support/mod.rs"]
mod support;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let output = args.next().ok_or_else(|| {
        anyhow::anyhow!(
            "usage: cargo run -p reforge-core --example make_fixture -- OUTPUT.iso [INPUT.exe]"
        )
    })?;
    let data = match args.next() {
        Some(path) => std::fs::read(path)?,
        None => support::pe(),
    };
    std::fs::write(output, support::iso(&data))?;
    Ok(())
}
