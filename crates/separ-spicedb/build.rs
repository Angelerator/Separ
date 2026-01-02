fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile SpiceDB proto files
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "proto/authzed/api/v1/permission_service.proto",
                "proto/authzed/api/v1/schema_service.proto",
                "proto/authzed/api/v1/watch_service.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
