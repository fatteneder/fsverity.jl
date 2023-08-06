using BinaryBuilder

name = "libfsverity"
version = v"1.5"
sources = [
    ArchiveSource("https://git.kernel.org/pub/scm/fs/fsverity/fsverity-utils.git/snapshot/fsverity-utils-1.5.tar.gz",
                  "830e38ec081ef8171eb210461cf8bee8a707c7c60f9018a4b567af145a510884")
]

script = raw"""
cd ${WORKSPACE}/srcdir/fsverity-utils-*
make USE_SHARED_LIB=1 CFLAGS='-std=c99 -Wno-missing-field-initializers'
install -Dvm 755 "fsverity" "${bindir}/fsverity"
install -Dvm 755 "libfsverity.so" "${libdir}/libfsvertiy.so"
install -Dvm 755 "libfsverity.so.0" "${libdir}/libfsverity.so.0"
"""

# platforms = supported_platforms()
platforms = [Platform("x86_64", "linux")]

products = [
    LibraryProduct("libfsverity", :libfsverity),
]

dependencies = [
    Dependency("OpenSSL_jll")
]

build_tarballs(ARGS, name, version, sources, script, platforms, products, dependencies;
              julia_compat="1.6")

