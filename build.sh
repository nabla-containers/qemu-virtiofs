mkdir build
( cd build; ../configure --disable-werror --target-list=x86_64-softmmu --enable-cap-ng --enable-seccomp --disable-slirp; make -j$(nproc) ; make virtiofsd memfsd )
