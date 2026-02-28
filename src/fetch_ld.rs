use crate::cpu_arch::CpuArch;
use crate::libc_deb;
use crate::libc_deb::download_and_extract;
use crate::libc_version::LibcVersion;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;
use version_compare::Cmp;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc deb error: {}", source))]
    Deb { source: libc_deb::Error },

    #[snafu(display("failed writing to linker file: {}", source))]
    Write { source: std::io::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Download linker compatible with libc version `ver` and save to directory
/// `dir`
pub fn fetch_ld(ver: &LibcVersion) -> Result {
    println!("{}", "fetching linker".green().bold());

    let deb_file_name = format!("libc6_{}.deb", ver);

    let ld_name = if version_compare::compare_to(&ver.string_short, "2.34", Cmp::Lt).unwrap() {
        format!("ld-{}.so", ver.string_short)
    } else {
        match ver.arch {
            CpuArch::I386 => "ld-linux.so.2",
            CpuArch::Amd64 => "ld-linux-x86-64.so.2",
        }
        .to_string()
    };
    let out_name = format!("ld-{}.so", ver.string_short);

    libc_deb::write_ubuntu_pkg_file(&deb_file_name, &ld_name, out_name).context(DebSnafu)?;
    Ok(())
}
pub fn fetch_pkg(ver: &str) -> Result {
    println!("{}", "fetching pkg".green().bold());
    let deb_file_name = format!("libc6_{}.deb", ver);
    download_and_extract(&deb_file_name);
    Ok(())
}
