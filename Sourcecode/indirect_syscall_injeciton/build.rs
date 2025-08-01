/*
    Linker composer .asm files.
    Compiles Windows resource (.rc) files into a Rust binary during the build process.
    Supports both GNU (windres.exe) and MSVC (rc.exe) toolchains.
    Emits Cargo directives to link the compiled resources into the final executable.
    Author: @5mukx
*/

use std::env;

use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;


fn main() -> Result<()> {

    let target = env::var("TARGET").expect("Missing TARGET environment variable");
    let out_dir = env::var("OUT_DIR").expect("Missing OUT_DIR environment variable");

    if !target.contains("x86_64") {
        panic!("This build script only supports x86_64 targets.");
    }

    if target.contains("msvc") {
        cc::Build::new()
            .file("src/asm/msvc/hellsasm.asm")
            .compile("hellsasm");
    } else if target.contains("gnu") {
        let sources = ["src/asm/gnu/hellsasm.asm"];
        if let Err(e) = nasm_rs::compile_library("hellsasm", &sources) {
            panic!("Failed to compile with NASM [hellsasm]: {}", e);
        }
        for source in &sources {
            println!("cargo:rerun-if-changed={}", source);
        }
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=hellsasm");
    } else {
        panic!("Unsupported target: {}", target);
    }

    // change metadata modification. !
    let mut builder = ResourceBuilder::new();

    builder
        .include("resources/include")
        .define("VERSION", Some("1.0"))
        .undefine("DEBUG")
        .compile("resources/resource.rc")
        .context("Resource compilation failed")?;

    Ok(())

}



#[cfg(target_env = "msvc")]
use find_winsdk::{SdkInfo, SdkVersion};

/// Custom error type for specific failure cases
#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Resource compiler not found: {0}")]
    CompilerNotFound(String),
    #[error("Invalid input filename: {0}")]
    InvalidFilename(String),
    #[error("OUT_DIR environment variable is invalid or not set")]
    InvalidOutDir,
    #[error("Resource compilation failed with exit code {0}")]
    CompilationFailed(i32),
    #[error("Resource compilation interrupted by signal")]
    CompilationInterrupted,
    #[error("Failed to write Cargo directives: {0}")]
    CargoDirectiveFailed(#[source] io::Error),
    #[cfg(target_env = "msvc")]
    #[error("Windows SDK error: {0}")]
    SdkError(#[source] std::io::Error),
}

// Builder for compiling Windows resources
#[derive(Clone, Debug, Default)]
pub struct ResourceBuilder {
    extra_include_dirs: Vec<PathBuf>,
    extra_cpp_defs: Vec<(String, Option<String>)>,
    cpp_undefs: Vec<String>,
}

impl ResourceBuilder {
    /// Creates a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an include path for preprocessing.
    pub fn include<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.extra_include_dirs.push(path.as_ref().to_path_buf());
        self
    }

    /// Adds a preprocessor definition.
    /// This is a a testing file
    pub fn define<'a, V: Into<Option<&'a str>>>(&mut self, name: &str, value: V) -> &mut Self {
        self.extra_cpp_defs
            .push((name.to_owned(), value.into().map(ToOwned::to_owned)));
        self
    }

    /// Adds a preprocessor symbol to undefine.
    pub fn undefine(&mut self, name: &str) -> &mut Self {
        self.cpp_undefs.push(name.to_owned());
        self
    }

    /// Compiles a Windows resource file (.rc).
    pub fn compile<P: AsRef<Path>>(&mut self, rc_file: P) -> Result<()> {
        let rc_file = rc_file.as_ref();
        let compiler = self
            .find_resource_compiler()
            .context("Failed to locate resource compiler")?;
        self.compile_resource(rc_file, &compiler)
            .context("Failed to compile resource")
    }

    /// Locates the resource compiler based on the target environment.
    fn find_resource_compiler(&self) -> Result<PathBuf> {
        #[cfg(target_env = "gnu")]
        {
            env::var_os("PATH")
                .and_then(|path| {
                    env::split_paths(&path)
                        .map(|p| p.join("windres.exe"))
                        .find(|p| p.exists())
                })
                .ok_or_else(|| {
                    ResourceError::CompilerNotFound("windres.exe not found in PATH".into())
                })
                .map_err(Into::into)
        }

        #[cfg(target_env = "msvc")]
        {
            // Define RC_EXE based on target architecture
            let rc_exe = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
                Ok("x86") => "x86/rc.exe",
                Ok("x86_64") => "x64/rc.exe",
                Ok("arm") => "arm/rc.exe",
                Ok("aarch64") => "arm64/rc.exe",
                _ => "x64/rc.exe", // Default to x64 if unknown
            };

            if let Some(bin_path) = env::var_os("WindowsSdkVerBinPath") {
                Ok(Path::new(&bin_path).join(rc_exe))
            } else {
                let sdk = SdkInfo::find(SdkVersion::Any)
                    .map_err(ResourceError::SdkError)?
                    .ok_or_else(|| {
                        ResourceError::CompilerNotFound("No Windows SDK installation found".into())
                    })?;
                let path_suffix = if sdk.product_version().starts_with("10.") {
                    format!("bin/{}.0/{}", sdk.product_version(), rc_exe)
                } else {
                    format!("bin/{}", rc_exe)
                };
                Ok(Path::new(sdk.installation_folder()).join(path_suffix))
            }
        }
    }

    /// Compiles the resource file using the specified compiler.
    fn compile_resource(&self, rc_file: &Path, compiler: &Path) -> Result<()> {
        let rc_filename = rc_file
            .file_name()
            .ok_or_else(|| ResourceError::InvalidFilename(rc_file.display().to_string()))?;
        let out_dir = env::var_os("OUT_DIR")
            .ok_or(ResourceError::InvalidOutDir)
            .map(PathBuf::from)?;

        // Compute output file and library name
        let (out_file, lib_name) = if cfg!(target_env = "gnu") {
            let mut libname = OsString::from("lib");
            libname.push(rc_filename);
            let out_file = out_dir.join(libname).with_extension("res.a");
            let lib_name = Path::new(rc_filename)
                .with_extension("res")
                .to_string_lossy()
                .into_owned();
            (out_file, lib_name)
        } else {
            let out_file = out_dir.join(rc_filename).with_extension("res.lib");
            let lib_name = out_file
                .file_stem()
                .ok_or_else(|| ResourceError::InvalidFilename(rc_file.display().to_string()))?
                .to_string_lossy()
                .into_owned();
            (out_file, lib_name)
        };

        // Build the command arguments
        let mut cmd = Command::new(compiler);

        // Add specfic options that the user needs
        for inc_path in &self.extra_include_dirs {
            cmd.arg(if cfg!(target_env = "gnu") {
                format!("-I{}", inc_path.display())
            } else {
                format!("/i{}", inc_path.display())
            });
        }
        for def in &self.extra_cpp_defs {
            let s = if let Some(ref v) = def.1 {
                format!("-D{}={}", def.0, v)
            } else {
                format!("-D{}", def.0)
            };
            cmd.arg(if cfg!(target_env = "gnu") { s } else { format!("/d{}", &s[2..]) });
        }
        for undef in &self.cpp_undefs {
            cmd.arg(if cfg!(target_env = "gnu") {
                format!("-U{}", undef)
            } else {
                format!("/u{}", undef)
            });
        }

        // Add toolchain-specific arguments
        if cfg!(target_env = "gnu") {
            cmd.args(&[
                OsStr::new("-Ocoff"),
                OsStr::new("-v"),
                OsStr::new("-c65001"),
                rc_file.as_os_str(),
                out_file.as_os_str(),
            ]);
        } else {
            let fo = format!("/fo{}", out_file.display());
            cmd.args(&[
                OsStr::new(&fo),
                OsStr::new("/v"),
                OsStr::new("/nologo"),
                OsStr::new("/c65001"),
                rc_file.as_os_str(),
            ]);
        }

        // Execute the command
        let status = cmd
            .status()
            .context("Failed to execute resource compiler")?;

        if !status.success() {
            return Err(if let Some(code) = status.code() {
                ResourceError::CompilationFailed(code)
            } else {
                ResourceError::CompilationInterrupted
            }
            .into());
        }

        // Emit Cargo directives
        let stdout = io::stdout();
        let mut stdout_lock = stdout.lock();
        write!(
            stdout_lock,
            "cargo:rustc-link-search=native={}\n",
            out_file.parent().unwrap().display()
        )
        .map_err(ResourceError::CargoDirectiveFailed)?;
        write!(
            stdout_lock,
            "cargo:rustc-link-lib={}\n",
            if cfg!(target_env = "gnu") {
                format!("static={}", lib_name)
            } else {
                lib_name
            }
        )
        .map_err(ResourceError::CargoDirectiveFailed)?;
        write!(
            stdout_lock,
            "cargo:rerun-if-changed={}\n",
            rc_file.display()
        )
        .map_err(ResourceError::CargoDirectiveFailed)?;

        Ok(())
    }
}
