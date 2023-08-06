module fsverity


using Base.Libc
import libfsverity_jll: libfsverity


# char      <--> Cchar (-)
# uint8_t   <--> Cuchar (UInt8)
# uint16_t  <--> Cushort (UInt16)
# uint32_t  <--> Cuint (UInt32)
# uint64_t  <--> Culonglong (Int64)
# uintptr_t <--> Cuint (?) (UInt32)
# void      <--> Cvoid (Nothing?)
# size_t    <--> Csize_t (UInt)


# copied from https://www.kernel.org/doc/html/latest/filesystems/fsverity.html, 5.8.2023
const FS_IOC_ENABLE_VERITY_CODES = Dict(
    Libc.EACCES       => "the process does not have write access to the file",
    Libc.EBADMSG      => "the builtin signature is malformed",
    Libc.EBUSY        => "this ioctl is already running on the file",
    Libc.EEXIST       => "the file already has verity enabled",
    Libc.EFAULT       => "the caller provided inaccessible memory",
    Libc.EFBIG        => "the file is too large to enable verity on",
    Libc.EINTR        => "the operation was interrupted by a fatal signal",
    Libc.EINVAL       => "unsupported version, hash algorithm, or block size; or reserved bits are set; or the file descriptor refers to neither a regular file nor a directory.",
    Libc.EISDIR       => "the file descriptor refers to a directory",
    Libc.EKEYREJECTED => "the builtin signature doesn't match the file",
    Libc.EMSGSIZE     => "the salt or builtin signature is too long",
    Libc.ENOKEY       => "the \".fs-verity\" keyring doesn't contain the certificate needed to verify the builtin signature",
    Libc.ENOPKG       => "fs-verity recognizes the hash algorithm, but it's not available in the kernel's crypto API as currently configured (e.g. for SHA-512, missing CONFIG_CRYPTO_SHA512).",
    Libc.ENOTTY       => "this type of filesystem does not implement fs-verity",
    Libc.EOPNOTSUPP   => "the kernel was not configured with fs-verity support; or the filesystem superblock has not had the 'verity' feature enabled on it; or the filesystem does not support fs-verity on this file. (See Filesystem support.)",
    Libc.EPERM        => "the file is append-only; or, a builtin signature is required and one was not provided.",
    Libc.EROFS        => "the filesystem is read-only",
    Libc.ETXTBSY      => "someone has the file open for writing. This can be the caller's file descriptor, another open file descriptor, or the file reference held by a writable memory map.",
)


const FS_VERITY_HASH_ALG_SHA256 = UInt32(1)
const FS_VERITY_HASH_ALG_SHA512 = UInt32(2)

struct libfsverity_metadata_callbacks
  ctx::Ptr{Cvoid}
  merkel_tree_size::Ptr{Cvoid} # int (*merkel_tree_size)(void *ctx, uint64_t size)
  merkel_tree_block::Ptr{Cvoid} # int (*merkel_tree_size)(void *ctx, void *block, size_t size, uint64_t size)
  descriptor::Ptr{Cvoid} # int (*descriptor)(void *ctx, const void *descriptor, size_t size)
end
function libfsverity_metadata_callbacks()
  libfsverity_metadata_callbacks(C_NULL, C_NULL, C_NULL, C_NULL)
end


struct libfsverity_merkle_tree_params
  version::Cuint
  hash_algorithm::Cuint
  file_size::Culonglong
  block_size::Cuint
  salt_size::Cuint
  salt::Ptr{Cchar}
  # reserved1::Vector{Culonglong}
  # reserved1::Vector{Int64}
  reserved1::Ptr{Int64}
  metadata_callbacks::libfsverity_metadata_callbacks
  # reserved2::Ptr{Cuint} # TODO uintptr_t?
  reserved2::Vector{Ptr{Int}}
end
function libfsverity_merkle_tree_params(fsize::UInt)
  libfsverity_merkle_tree_params(UInt32(1), UInt32(0), fsize, UInt32(0), UInt32(0), Ptr{Cchar}(),
                                 Ptr{Int64}(), libfsverity_metadata_callbacks(), Ptr{Int}[])
end


struct libfsverity_digest
  digest_algorithm::Cushort
  digest_size::Cushort
  digest::Cuchar
end


struct libfsverity_signature_params
  keyfile::Ptr{Cchar}
  certfile::Ptr{Cchar}
  reserved1::Ptr{Culonglong}
  pkcs11_engine::Ptr{Cchar}
  pkcs11_module::Cchar
  pkcs11_keyid::Cchar
  reserved2::Ptr{Cuint}
end


# Q: What's the purpose of this read function? Couldn't libfsverity_compute_digest wrap
# this itself behind the scenes?
# I think this is a safety measure to deliver an opaque file pointer.
# TODO Fn signature correct with C types? I mean it will only be called from C, so ...
function libfsverity_read_fn(fd::Ptr{Cvoid}, buf::Ptr{Cvoid}, count::Csize_t)::Cint
  if fd === C_NULL
    return -1
  elseif buf === C_NULL
    return -2
  else
    unsafe_copy!(buf, fd, count)
    return 0
  end
end


# requires libfsverity_enable to return 0
function libfsverity_compute_digest(fd::Ptr{Cvoid},
    params::libfsverity_merkle_tree_params, digest_ret::Vector{Vector{libfsverity_digest}})

  read_fn = @cfunction(libfsverity_read_fn, Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t))
  ccall((:libfsverity_compute_digest, libfsverity), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ref{libfsverity_merkle_tree_params}, Ptr{Ptr{libfsverity_digest}}),
        fd, read_fn, Ref(params), digest_ret)
end


# requires libfsverity_enable to return 0
function libfsverity_sign_digest(digest::libfsverity_digest,
    sig_params::libfsverity_signature_params)

  ptr_sig_ret = Ptr{Cuchar}()
  sig_size_ret = Csize_t(0)

  ret = ccall((:libfsverity_sign_digest, libfsverity), Cint,
        (Ref{libfsverity_digest}, Ref{libfsverity_signature_params}, Ptr{Ptr{Cuchar}}, Ptr{Csize_t}),
        digest, sig_params, Ref(ptr_sig_ret), Ref(sig_size_ret))

  if ret == 0
    # success
  elseif ret == -Libc.EINVAL

  elseif ret == -Libc.EBADMSG

  elseif ret < 0

  else
    error("unknown return code")
  end

  sig_ret = unsafe_string(ptr_sig_ret, sig_size_ret)
  Libc.free(ptr_sig_ret)

  return sig_ret
end


"""
  libfsverity_enable(io::IO, params::libfsverity_merkle_tree_params)::Nothing

TODO This should not do error handling or?
"""
function libfsverity_enable(io::IO, params::libfsverity_merkle_tree_params)
  ret = ccall((:libfsverity_enable, libfsverity), Cint,
        (Cint, Ref{libfsverity_merkle_tree_params}),
        fd(io), Ref(params))

  if ret == 0
    return
  elseif ret == -Libc.EINVAL
    error("invalid arguments to libfsverity_enable")
  elseif haskey(FS_IOC_ENABLE_VERITY_CODES, -ret)
    error(FS_IOC_ENABLE_VERITY_CODES[-ret])
  else
    error("unknown return code $ret")
  end

end


# same error handling as libfsverity_enable
function libfsverity_enable_with_sig(fd::Int, params::libfsverity_merkle_tree_params,
    sig::UInt8, sig_size::UInt)
  ccall((:libfsverity_enable_with_sig, libfsverity), Int,
        (Int, Ptr{libfsverity_merkle_tree_params}, UInt8, UInt),
        fd, params, sig, sig_size)
end


"""
  libfsverity_find_hash_alg_by_name(name::AbstractString)::UInt32

Return the hash algorithm number, or zero if not found.
"""
function libfsverity_find_hash_alg_by_name(name::AbstractString)
  ccall((:libfsverity_find_hash_alg_by_name, libfsverity), UInt32,
        (Ptr{Cchar},),
        name)
end


"""
  libfsverity_get_digest_size(alg_num::UInt32)::Int

Return size of digest in bytes, or -1 if algorithm is unknown.
"""
function libfsverity_get_digest_size(alg_num::UInt32)
  ccall((:libfsverity_get_digest_size, libfsverity), Int,
        (UInt32,),
        alg_num)
end


"""
  libfsverity_get_hash_name(alg_num::UInt32)::Union{String,Nothing}

Return name of the hash algorithm, or nothing if algorithm is unknown.
"""
function libfsverity_get_hash_name(alg_num::UInt32)
  cstr = ccall((:libfsverity_get_hash_name, libfsverity), Ptr{Cchar},
        (UInt32,),
        alg_num)
  str = cstr != C_NULL ? unsafe_string(cstr) : nothing
  return str
end


# function libfsverity_set_error_callback(cb::Ptr{Cvoid})
# TODO How does this work?
function libfsverity_set_error_callback(cb::Function)
  ccall(( :libfsverity_set_error_callback, libfsverity), Cvoid,
        (Ptr{Cvoid},),
        cb)
end


end # module libfsverity
