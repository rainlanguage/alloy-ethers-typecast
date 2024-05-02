fn main() {
    let file_path = "./contracts/IMulticall3.sol";
    let file_url = "https://raw.githubusercontent.com/mds1/multicall/1d08785d1c2e817105ca34c7c7b126297a258017/src/interfaces/IMulticall3.sol";
    std::fs::create_dir_all("./contracts").expect("failed to create 'contracts' directory");
    std::process::Command::new("curl")
        .args(["-s", "-o", file_path, file_url])
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
