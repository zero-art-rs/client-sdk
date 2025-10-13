use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["protos/zero_art.proto"], &["proto"])?;
    Ok(())
}
