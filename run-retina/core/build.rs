use bindgen::Builder;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;

const DPDK_VERSION: &str = "21.11";
const DPDK_GIT_REPO: &str = "https://dpdk.org/git/dpdk";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/dpdk/inline.c");

    // modified from https://github.com/deeptir18/cornflakes/blob/master/cornflakes-libos/build.rs
    let pwd = fs::canonicalize(PathBuf::from("./")).unwrap();

    // // Download DPDK source from the official git repo.
    // if !Path::new("deps/dpdk").is_dir() {
    //     let mut tag = "v".to_string();
    //     tag.push_str(DPDK_VERSION);
    //     let res = Command::new("git")
    //         .args(&["clone", "-b", &tag, DPDK_GIT_REPO, "deps/dpdk"])
    //         .status()
    //         .expect("Please install git.");
    //     if !res.success() {
    //         panic!(
    //             "Failed to clone DPDK repo {} at tag {}.",
    //             DPDK_GIT_REPO, &tag
    //         );
    //     }
    // }

    // // Configure DPDK with meson.
    // if !Path::new("deps/configure-finish").is_file() {
    //     // Remove dpdk/build directory if they exist.
    //     let build_dir = Path::new("deps/dpdk/build");
    //     if build_dir.is_dir() {
    //         fs::remove_dir_all(build_dir)
    //             .expect("Fail to remove existing deps/dpdk/build directory.");
    //     }

    //     // Configure DPDK for build.
    //     let mut meson_dprefix = String::from("-Dprefix=");
    //     meson_dprefix.push_str(pwd.join("deps/dpdk-install").to_str().unwrap());
    //     let res = Command::new("meson")
    //         .current_dir("deps/dpdk")
    //         .args(&[&meson_dprefix[..], "build"])
    //         .status()
    //         .expect("Please install meson.");
    //     if !res.success() {
    //         panic!("Fail to configure DPDK source with meson.");
    //     }

    //     fs::File::create(Path::new("deps/configure-finish"))
    //         .expect("Fail to create deps/configure-finish.");
    //     println!("cargo:rerun-if-changed=deps/configure-finish");
    // }


    // // Build and install DPDK.
    // let res = Command::new("ninja")
    //     .current_dir("deps/dpdk/build")
    //     .status()
    //     .expect("Please install ninja.");
    // if !res.success() {
    //     panic!("Failed to build DPDK with ninja.");
    // }
    // let res = Command::new("ninja")
    //     .current_dir("deps/dpdk/build")
    //     .args(&["install"])
    //     .status()
    //     .unwrap();
    // assert!(res.success());

    // Set PKG_CONFIG_PATH environment variable to point to the installed DPDK library.
    let pkg_config_path = pwd.join("deps/dpdk-install/lib/x86_64-linux-gnu/pkgconfig");
    env::set_var(
        "PKG_CONFIG_PATH",
        &pkg_config_path
            .to_str()
            .unwrap(),
    );

    // Check DPDK version.
    let output = Command::new("pkg-config")
        .args(&["--modversion", "libdpdk"])
        .output()
        .expect("Please install pkg-config.");
    if !output.status.success() {
        panic!(
            "Failed to find dpdk cflags. DPDK is not successfully installed by the build script."
        )
    }
    let s = String::from_utf8(output.stdout).unwrap();
    let version_str = s.trim();
    if !version_str.starts_with(DPDK_VERSION) {
        panic!(
            "pkg-config finds another DPDK library with version {}.",
            version_str
        );
    }

    // Probe the cflags of the installed DPDK library.
    let output = Command::new("pkg-config")
        .args(&["--cflags", "libdpdk"])
        .output()
        .unwrap();
    assert!(output.status.success() == true);
    let cflags = String::from_utf8(output.stdout).unwrap();


    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cargo_dir = Path::new(&cargo_manifest_dir);

    let out_dir_s = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_s);

    let mut header_locations = vec![];

    for flag in cflags.split(' ') {
        if let Some(stripped) = flag.strip_prefix("-I") {
            let header_location = stripped.trim();
            header_locations.push(header_location);
        }
    }

    let ldflags_bytes = Command::new("pkg-config")
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .args(&["--libs", "libdpdk"])
        .output()
        .unwrap_or_else(|e| panic!("Failed pkg-config ldflags: {:?}", e))
        .stdout;

    if ldflags_bytes.is_empty() {
        println!("Could not get DPDK's LDFLAGS.");
        exit(1);
    };

    let ldflags = String::from_utf8(ldflags_bytes).unwrap();

    let mut library_location = None;
    let mut lib_names = vec![];

    for flag in ldflags.split(' ') {
        if let Some(stripped) = flag.strip_prefix("-L") {
            library_location = Some(stripped);
        } else if let Some(stripped) = flag.strip_prefix("-l") {
            lib_names.push(stripped);
        }
    }

    // Link in `librte_net_mlx5` and its dependencies if desired.
    #[cfg(feature = "mlx5")]
    {
        lib_names.extend(&[
            "rte_net_mlx5",
            "rte_bus_pci",
            "rte_bus_vdev",
            "rte_common_mlx5",
        ]);
    }

    // Step 1: Now that we've compiled and installed DPDK, point cargo to the libraries.
    println!(
        "cargo:rustc-link-search=native={}",
        library_location.unwrap()
    );
    for lib_name in &lib_names {
        println!("cargo:rustc-link-lib={}", lib_name);
    }

    // Step 2: Generate bindings for the DPDK headers.
    let mut builder = Builder::default();
    for header_location in &header_locations {
        builder = builder.clang_arg(&format!("-I{}", header_location));
    }

    let headers_file = Path::new(&cargo_dir)
        .join("src")
        .join("dpdk")
        .join("dpdk_headers.h");
    let bindings = builder
        .header(headers_file.to_str().unwrap())
        // mark as opaque per bindgen bug on packed+aligned structs:
        // https://github.com/rust-lang/rust-bindgen/issues/1538
        .opaque_type(r"rte_arp_ipv4|rte_arp_hdr")
        .opaque_type(r"(rte_ecpri|rte_l2tpv2)_.*")
        .allowlist_type(r"(rte|eth|pcap)_.*")
        .allowlist_function(r"(_rte|rte|eth|numa|pcap)_.*")
        .allowlist_var(r"(RTE|DEV|ETH|MEMPOOL|PKT|rte)_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap_or_else(|e| panic!("Failed to generate bindings: {:?}", e));
    let bindings_out = out_dir.join("dpdk.rs");
    bindings
        .write_to_file(bindings_out)
        .expect("Failed to write bindings");

    // Step 3: Compile a stub file so Rust can access `inline` functions in the headers
    // that aren't compiled into the libraries.
    let mut builder = cc::Build::new();
    builder.opt_level(3);
    builder.pic(true);
    builder.flag("-march=native");

    let inlined_file = Path::new(&cargo_dir)
        .join("src")
        .join("dpdk")
        .join("inlined.c");
    builder.file(inlined_file.to_str().unwrap());
    for header_location in &header_locations {
        builder.include(header_location);
    }
    builder.compile("inlined");
}
