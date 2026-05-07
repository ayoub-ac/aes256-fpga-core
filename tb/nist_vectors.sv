// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// NIST FIPS-197 / NIST SP 800-38A AES-256 reference test vectors.
//
// Informational; consumed by tb/sim_main.cpp via a separate C++ table.
// Kept here as plain SystemVerilog so external simulators (Icarus, VCS)
// can pull the same vectors via `include if needed.
//
// Sources:
//   - NIST FIPS-197, Appendix C.3 (AES-256 known-answer vector)
//   - NIST SP 800-38A, Appendix F.1.5 / F.1.6 (ECB-AES256, four blocks)

`ifndef NIST_VECTORS_AES256_SV
`define NIST_VECTORS_AES256_SV

package nist_vectors_aes256_pkg;

  // FIPS-197 Appendix C.3
  parameter logic [255:0] KEY_FIPS_C3 =
      256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
  parameter logic [127:0] PT_FIPS_C3  = 128'h00112233445566778899aabbccddeeff;
  parameter logic [127:0] CT_FIPS_C3  = 128'h8ea2b7ca516745bfeafc49904b496089;

  // NIST SP 800-38A F.1.5 ECB-AES256 (shared key for all four blocks)
  parameter logic [255:0] KEY_NIST_38A =
      256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;

  // Block 1
  parameter logic [127:0] PT_NIST_38A_1 = 128'h6bc1bee22e409f96e93d7e117393172a;
  parameter logic [127:0] CT_NIST_38A_1 = 128'hf3eed1bdb5d2a03c064b5a7e3db181f8;

  // Block 2
  parameter logic [127:0] PT_NIST_38A_2 = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
  parameter logic [127:0] CT_NIST_38A_2 = 128'h591ccb10d410ed26dc5ba74a31362870;

  // Block 3
  parameter logic [127:0] PT_NIST_38A_3 = 128'h30c81c46a35ce411e5fbc1191a0a52ef;
  parameter logic [127:0] CT_NIST_38A_3 = 128'hb6ed21b99ca6f4f9f153e7b1beafed1d;

  // Block 4
  parameter logic [127:0] PT_NIST_38A_4 = 128'hf69f2445df4f9b17ad2b417be66c3710;
  parameter logic [127:0] CT_NIST_38A_4 = 128'h23304b7a39f9f3ff067d8d8f9e24ecc7;

endpackage

`endif
