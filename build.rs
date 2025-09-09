use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/zero_art.proto"], &["proto"])?;
    Ok(())
}
