using Base.Libc
using fsverity


fname = joinpath(@__DIR__, "test")
touch(fname)
fsize = filesize(fname)

prms = fsverity.libfsverity_merkle_tree_params(UInt(fsize))
open(fname, "r") do f
  ret = fsverity.libfsverity_enable(f, prms)
  if ret == 0
    println("SUCCESS")
  elseif ret == -Libc.EINVAL
    println("invalid arguments to libfsverity_enable")
  elseif haskey(fsverity.FS_IOC_ENABLE_VERITY_CODES, -ret)
    println(fsverity.FS_IOC_ENABLE_VERITY_CODES[-ret])
  else
    println("unknown return code")
  end
  # display(ret)
  # display(Libc.strerror(ret))
  # TODO Map ret codes to named error codes and back to FS_IOC_ENABLE_VERITY codes
end

isfile(fname) && remove(fname, force=true)
