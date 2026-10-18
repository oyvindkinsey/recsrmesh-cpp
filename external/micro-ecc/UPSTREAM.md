# micro-ecc

Vendored from https://github.com/kmackay/micro-ecc at commit 541b3a7
(BSD-2-Clause, see LICENSE.txt). Only secp192r1 is compiled
(`src/uecc_p192.c`, portable C, no asm includes) for CSRMesh MASP ECDH,
which Mbed TLS 4 no longer provides. Files are unmodified upstream.
