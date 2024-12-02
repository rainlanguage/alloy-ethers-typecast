fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("Failed to get manifest directory");
    let contracts_dir = format!("{}/contracts", manifest_dir);
    let file_path = format!("{}/IMulticall3.sol", contracts_dir);

    let file_url = "https://raw.githubusercontent.com/mds1/multicall/1d08785d1c2e817105ca34c7c7b126297a258017/src/interfaces/IMulticall3.sol";

    std::fs::create_dir_all(&contracts_dir).expect("failed to create 'contracts' directory");
    std::process::Command::new("curl")
        .args(["-s", "-o", &*file_path, file_url])
        .status()
        .expect("Failed to get IMulticall3 contract abi!")
        .success()
        .then(|| {
            std::fs::read_to_string(file_path)
                .expect("Failed to get IMulticall3 contract abi!")
                .contains("404: Not Found")
                .then(|| {
                    panic!(
                        "{}",
                        "Failed to get IMulticall3 contract abi, 404: Not Found"
                    )
                })
                .unwrap_or(())
        })
        .expect("Failed to get IMulticall3 contract abi!")
}
