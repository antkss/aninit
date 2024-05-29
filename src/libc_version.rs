//! Libc version operations

use crate::cpu_arch;
use crate::cpu_arch::CpuArch;

use std::fmt;
use std::path::Path;
use std::str;
use std::fs::File;
// use std::env;
use ex::fs;
use ex::io;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;
// use twoway::find_bytes;
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::io::Read;
use std::process::Stdio; // Import Stdio
use once_cell::sync::OnceCell;
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::io::Write;
// use std::io::ErrorKind;
static HOME_DIR: OnceCell<String> = OnceCell::new();

fn init_home_dir() -> String {
    let home = env::var("HOME").unwrap_or_else(|_| {
        env::var("USERPROFILE").unwrap_or_else(|_| {
            panic!("Could not find home directory path. Neither HOME nor USERPROFILE environment variables are set.");
        })
    });
    home.to_string()
}

fn update_list() {
    // Embed the update_list file into the binary
    let update_list_bytes = include_bytes!("update_list.py");

    // Define the cache directory and destination path
    let cache_dir = HOME_DIR.get_or_init(init_home_dir).to_string() + "/.cache";
    let update_list_path = Path::new(&cache_dir).join("update_list.py");

    // Create the cache directory if it does not exist
    fs::create_dir_all(cache_dir).expect("Failed to create cache directory");

    // Write the embedded file to the destination
    let mut file = File::create(&update_list_path).expect("Failed to create file in cache");
    file.write_all(update_list_bytes).expect("Failed to write to file");

    // Make the file executable
    let mut perms = fs::metadata(&update_list_path).expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&update_list_path, perms).expect("Failed to set permissions");

    // Execute the file
    let output = Command::new("python3")
        .arg(&update_list_path)
        .output()
        .expect("Failed to execute the update_list");
    // Print the output of the executed file
    println!("output: {}", String::from_utf8_lossy(&output.stdout));
}

fn choose_one(filename: &str, arch: &str, version: &str) -> String {
    let file = File::open(filename).unwrap_or_else(|_| {
                println!("{} not found. Updating list...",filename);
                update_list();
                println!("please run command again !!");
                std::process::exit(1);
        }
    );
    let reader = BufReader::new(file);

    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    if lines.is_empty() {
        return String::new(); // Return an empty string if no lines are found
    }

    // Filter lines that contain the specified version and architecture
    let filtered_lines: Vec<String> = lines.into_iter().filter(|line| {
        line.contains(version) && line.contains(arch)
    }).collect();

    if filtered_lines.is_empty() {
        return String::new(); // Return an empty string if no matching lines are found
    }

    // Choose the first line from the filtered lines
    filtered_lines[0].clone()
}
fn find_libc_version(libc_path: &str) -> String {
    let libversion: Vec<&str> = vec!["2.39", "2.38", "2.37", "2.35", "2.31", "2.27", "2.23"];

    // Execute `strings`
    let strings_process = Command::new("strings")
        .arg(libc_path)
        .stdout(Stdio::piped()) // Capture stdout of `strings`
        .spawn()
        .expect("Failed to execute strings");

    // Get the stdout of `strings`
    let mut strings_output = strings_process.stdout.unwrap();

    // Read the output of `strings` into a buffer
    let mut strings_buffer = String::new();
    strings_output.read_to_string(&mut strings_buffer).unwrap();

    // Search for versions in the strings buffer
    for i in 0..libversion.len() {
        if strings_buffer.contains(libversion[i]) {
            return libversion[i].to_string();
        }
    }

    return "noversion".to_string();
}
/// Libc version information
pub struct LibcVersion {
    /// Long string representation of a libc version
    ///
    /// Example: `"2.23-0ubuntu10"`
    pub string: String,

    /// Short string representation of a libc version
    ///
    /// Example: `"2.23"`
    pub string_short: String,

    /// Architecture of libc
    pub arch: CpuArch,
}

impl fmt::Display for LibcVersion {
    /// Write libc version in format used by Ubuntu repositories
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.string)
    }
}

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed reading file: {}", source))]
    ReadError { source: io::Error },

    #[snafu(display("failed finding version string"))]
    NotFoundError,

    #[snafu(display("invalid architecture: {}", source))]
    ArchError { source: cpu_arch::Error },

    #[snafu(display("invalid UTF-8 in version string: {}", source))]
    Utf8Error { source: str::Utf8Error },
}

pub type Result<T> = std::result::Result<T, Error>;

impl LibcVersion {
    /// Detect the version of a libc
    pub fn detect(libc: &Path) -> Result<Self> {
        let bytes = fs::read(libc).context(ReadSnafu)?;
        // let string = Self::version_string_from_bytes(&bytes)?;
        // let string_short = string.split('-').next().context(NotFoundSnafu)?.to_string();
        let arch = CpuArch::from_elf_bytes(libc, &bytes).context(ArchSnafu)?;
        let string_short = find_libc_version(libc.to_str().context(NotFoundSnafu)?);

        let string = choose_one((HOME_DIR.get_or_init(init_home_dir).to_string()+"/.list").as_str(),arch.to_string().as_str(),string_short.as_str());

        println!("version id: {}",string);
        println!("arch: {}",arch.to_string());
        println!("ld is followed by current libc version, not version id");
        // println!("{}\n",string_shorts);

        Ok(Self {
            string,
            string_short,
            arch,
        })
    }

    // Extract the long version string from the bytes of a libc
    // fn version_string_from_bytes(libc: &[u8]) -> Result<String> {
    //     let split: [&[u8]; 2] = [
    //         b"GNU C Library (Ubuntu GLIBC ",
    //         b"GNU C Library (Ubuntu EGLIBC ",
    //     ];
    //     let pos = split
    //         .iter()
    //         .find_map(|cut| {
    //             let pos = find_bytes(libc, cut);
    //             Some(pos? + cut.len())
    //         })
    //         .context(NotFoundSnafu)?;
    //     let ver_str = &libc[pos..];
    //     let pos = ver_str
    //         .iter()
    //         .position(|&c| c == b')')
    //         .context(NotFoundSnafu)?;
    //     let ver_str = &ver_str[..pos];
    //     let ver_str = std::str::from_utf8(ver_str).context(Utf8Snafu)?.to_string();
    //     Ok(ver_str)
    // }
}
