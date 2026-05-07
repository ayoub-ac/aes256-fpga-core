// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// AES single-round combinational logic (FIPS-197 section 5).
//
// The round transformation is identical for AES-128, AES-192 and AES-256;
// only the number of rounds and the key schedule differ. This module is
// therefore reused without modification by `aes256_core`.
//
// Forward round (encrypt):
//   state -> SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
//   final round (round Nr) skips MixColumns
//
// Inverse round (decrypt), classic non-equivalent inverse cipher
// (FIPS-197 section 5.3):
//   state -> InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
//   final inverse round skips InvMixColumns.
//
// State layout: 128 bits, byte index = row + 4*col, byte 0 = state[127:120].

module aes_round (
  input  logic [127:0] state_i,
  input  logic [127:0] round_key_i,
  input  logic         encrypt_i,    // 1 = forward, 0 = inverse
  input  logic         final_round_i, // 1 = skip MixColumns / InvMixColumns
  output logic [127:0] state_o
);

  // GF(2^8) doubling: x*02 mod 0x11b.
  function automatic logic [7:0] xtime (input logic [7:0] b);
    xtime = {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
  endfunction

  // ---------- Unpack state ----------------------------------------------------
  logic [7:0] s [0:15];
  genvar gi;
  generate
    for (gi = 0; gi < 16; gi++) begin : g_unpack
      assign s[gi] = state_i[127 - 8*gi -: 8];
    end
  endgenerate

  // ---------- ENCRYPT PATH ----------------------------------------------------
  // SubBytes
  logic [7:0] sb [0:15];
  generate
    for (gi = 0; gi < 16; gi++) begin : g_sb
      aes_sbox u_sb (.in_i(s[gi]), .out_o(sb[gi]));
    end
  endgenerate

  // ShiftRows on sb -> sr.
  // Row r of column c at byte index r + 4*c is rotated left by r positions.
  logic [7:0] sr [0:15];
  assign sr[0]  = sb[0];
  assign sr[4]  = sb[4];
  assign sr[8]  = sb[8];
  assign sr[12] = sb[12];
  assign sr[1]  = sb[5];
  assign sr[5]  = sb[9];
  assign sr[9]  = sb[13];
  assign sr[13] = sb[1];
  assign sr[2]  = sb[10];
  assign sr[6]  = sb[14];
  assign sr[10] = sb[2];
  assign sr[14] = sb[6];
  assign sr[3]  = sb[15];
  assign sr[7]  = sb[3];
  assign sr[11] = sb[7];
  assign sr[15] = sb[11];

  // MixColumns: per-column GF(2^8) matrix multiply with [02 03 01 01;
  // 01 02 03 01; 01 01 02 03; 03 01 01 02]. xtime(a) = 02*a, (xtime(a) ^ a) = 03*a.
  logic [7:0] mc [0:15];
  genvar gc;
  generate
    for (gc = 0; gc < 4; gc++) begin : g_mc
      logic [7:0] a0, a1, a2, a3;
      assign a0 = sr[4*gc + 0];
      assign a1 = sr[4*gc + 1];
      assign a2 = sr[4*gc + 2];
      assign a3 = sr[4*gc + 3];
      assign mc[4*gc + 0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
      assign mc[4*gc + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
      assign mc[4*gc + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
      assign mc[4*gc + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    end
  endgenerate

  // Final round skips MixColumns.
  logic [127:0] enc_pre_ark;
  generate
    for (gi = 0; gi < 16; gi++) begin : g_enc_pre
      assign enc_pre_ark[127 - 8*gi -: 8] = final_round_i ? sr[gi] : mc[gi];
    end
  endgenerate

  logic [127:0] enc_out;
  assign enc_out = enc_pre_ark ^ round_key_i;

  // ---------- DECRYPT PATH ----------------------------------------------------
  // InvShiftRows on s -> isr.
  logic [7:0] isr [0:15];
  assign isr[0]  = s[0];
  assign isr[4]  = s[4];
  assign isr[8]  = s[8];
  assign isr[12] = s[12];
  assign isr[1]  = s[13];
  assign isr[5]  = s[1];
  assign isr[9]  = s[5];
  assign isr[13] = s[9];
  assign isr[2]  = s[10];
  assign isr[6]  = s[14];
  assign isr[10] = s[2];
  assign isr[14] = s[6];
  assign isr[3]  = s[7];
  assign isr[7]  = s[11];
  assign isr[11] = s[15];
  assign isr[15] = s[3];

  // InvSubBytes
  logic [7:0] isb [0:15];
  generate
    for (gi = 0; gi < 16; gi++) begin : g_isb
      aes_inv_sbox u_isb (.in_i(isr[gi]), .out_o(isb[gi]));
    end
  endgenerate

  // AddRoundKey
  logic [127:0] dec_after_ark;
  generate
    for (gi = 0; gi < 16; gi++) begin : g_dec_ark
      assign dec_after_ark[127 - 8*gi -: 8] = isb[gi] ^ round_key_i[127 - 8*gi -: 8];
    end
  endgenerate

  // InvMixColumns: per-column matrix multiply with [0e 0b 0d 09; 09 0e 0b 0d;
  // 0d 09 0e 0b; 0b 0d 09 0e]. Decompose 09=8+1, 0b=8+2+1, 0d=8+4+1, 0e=8+4+2,
  // sharing xtime cascades x2 = 02*b, x4 = 02*x2, x8 = 02*x4 per byte.
  logic [7:0] dak [0:15];
  generate
    for (gi = 0; gi < 16; gi++) begin : g_dak
      assign dak[gi] = dec_after_ark[127 - 8*gi -: 8];
    end
  endgenerate

  logic [7:0] imc [0:15];
  generate
    for (gc = 0; gc < 4; gc++) begin : g_imc
      logic [7:0] b0, b1, b2, b3;
      logic [7:0] x2_0, x4_0, x8_0;
      logic [7:0] x2_1, x4_1, x8_1;
      logic [7:0] x2_2, x4_2, x8_2;
      logic [7:0] x2_3, x4_3, x8_3;
      logic [7:0] m9_0, mb_0, md_0, me_0;
      logic [7:0] m9_1, mb_1, md_1, me_1;
      logic [7:0] m9_2, mb_2, md_2, me_2;
      logic [7:0] m9_3, mb_3, md_3, me_3;

      assign b0 = dak[4*gc + 0];
      assign b1 = dak[4*gc + 1];
      assign b2 = dak[4*gc + 2];
      assign b3 = dak[4*gc + 3];

      assign x2_0 = xtime(b0);  assign x4_0 = xtime(x2_0);  assign x8_0 = xtime(x4_0);
      assign x2_1 = xtime(b1);  assign x4_1 = xtime(x2_1);  assign x8_1 = xtime(x4_1);
      assign x2_2 = xtime(b2);  assign x4_2 = xtime(x2_2);  assign x8_2 = xtime(x4_2);
      assign x2_3 = xtime(b3);  assign x4_3 = xtime(x2_3);  assign x8_3 = xtime(x4_3);

      assign m9_0 = x8_0 ^ b0;          assign mb_0 = x8_0 ^ x2_0 ^ b0;
      assign md_0 = x8_0 ^ x4_0 ^ b0;   assign me_0 = x8_0 ^ x4_0 ^ x2_0;
      assign m9_1 = x8_1 ^ b1;          assign mb_1 = x8_1 ^ x2_1 ^ b1;
      assign md_1 = x8_1 ^ x4_1 ^ b1;   assign me_1 = x8_1 ^ x4_1 ^ x2_1;
      assign m9_2 = x8_2 ^ b2;          assign mb_2 = x8_2 ^ x2_2 ^ b2;
      assign md_2 = x8_2 ^ x4_2 ^ b2;   assign me_2 = x8_2 ^ x4_2 ^ x2_2;
      assign m9_3 = x8_3 ^ b3;          assign mb_3 = x8_3 ^ x2_3 ^ b3;
      assign md_3 = x8_3 ^ x4_3 ^ b3;   assign me_3 = x8_3 ^ x4_3 ^ x2_3;

      assign imc[4*gc + 0] = me_0 ^ mb_1 ^ md_2 ^ m9_3;
      assign imc[4*gc + 1] = m9_0 ^ me_1 ^ mb_2 ^ md_3;
      assign imc[4*gc + 2] = md_0 ^ m9_1 ^ me_2 ^ mb_3;
      assign imc[4*gc + 3] = mb_0 ^ md_1 ^ m9_2 ^ me_3;
    end
  endgenerate

  // Final inverse round skips InvMixColumns.
  logic [127:0] dec_out;
  generate
    for (gi = 0; gi < 16; gi++) begin : g_dec_out
      assign dec_out[127 - 8*gi -: 8] = final_round_i ? dak[gi] : imc[gi];
    end
  endgenerate

  // ---------- Mode select -----------------------------------------------------
  assign state_o = encrypt_i ? enc_out : dec_out;

endmodule
