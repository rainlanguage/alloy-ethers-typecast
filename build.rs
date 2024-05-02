use std::fs;
use std::process::Command;

fn main() {
    fs::create_dir_all("./contracts").expect("failed to create 'contracts' directory");

    let output_file = "./contracts/IMulticall3.sol";
    let status = Command::new("curl")
        .args([
            "-s",
            "-o",
            output_file,
            "https://raw.githubusercontent.com/mds1/multicall/1d08785d1c2e817105ca34c7c7b126297a258017/src/interfaces/IMulticall3.sol"
        ])
        .status()
        .expect("Failed to get IMulticall3.sol contract!");

    if !status.success() {
        panic!("Failed to get IMulticall3.sol contract!");
    }
}
