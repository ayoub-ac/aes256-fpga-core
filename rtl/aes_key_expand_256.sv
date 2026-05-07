// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// AES-256 key expansion step (FIPS-197 section 5.2).
//
// AES-256 has Nk = 8, Nr = 14, so the schedule W[0..59] has 60 32-bit words
// (15 round keys * 4 words = 1920 bits total). W[0..7] is the cipher key.
//
// For i in [8 .. 59]:
//   temp = W[i-1]
//   if      (i mod 8) == 0  ->  temp = SubWord(RotWord(temp)) ^ Rcon[i/8]
//   else if (i mod 8) == 4  ->  temp = SubWord(temp)            <- AES-256-only step
//   W[i] = W[i-8] ^ temp
//
// The "extra" SubWord at (i mod 8) == 4 is the only structural difference from
// the AES-128 schedule. It does not appear in AES-128 or AES-192.
//
// This module performs ONE step that consumes the previous 8 words
// (W[i-8 .. i-1] = 256 bits, MSB = W[i-8], LSB = W[i-1]) and produces the next
// 8 words (W[i .. i+7]) using a single Rcon byte for the (i mod 8) == 0 word.
//
// Cipher key is loaded directly as the first 8 words (rk[0] = W[0..3],
// rk[1] = W[4..7]); the FSM then runs this step 6 more times to fill the
// schedule, plus a 7th "final" step that produces only W[56..59] = rk[14]
// (the upper 4 words of that last 256-bit slab are unused).
//
// rcon_i: the Rcon byte applied to W[i-1] after RotWord+SubWord, for the
// (i mod 8) == 0 word at the bottom of the previous slab. For step k that
// produces W[8k..8k+7], rcon_i = rc[k], where:
//   rc[1]=01, rc[2]=02, rc[3]=04, rc[4]=08, rc[5]=10, rc[6]=20, rc[7]=40
// (FIPS-197 Appendix A.3). AES-256 only uses rc[1..7], because the schedule
// terminates after producing W[56..59] = rk[14].

module aes_key_expand_256 (
  input  logic [255:0] prev_block_i,  // W[i-8 .. i-1], MSB-first (W[i-8] in [255:224])
  input  logic [7:0]   rcon_i,        // Rcon[k] = rc[k], applied to the i = 8k word
  output logic [255:0] next_block_o   // W[i .. i+7]
);

  // Word layout: prev_block_i = { W0 .. W7 }, MSB first.
  //   W0 = prev_block_i[255:224]  (oldest, "W[i-8]")
  //   W7 = prev_block_i[31:0]     (newest, "W[i-1]")
  logic [31:0] w [0:7];
  assign w[0] = prev_block_i[255:224];
  assign w[1] = prev_block_i[223:192];
  assign w[2] = prev_block_i[191:160];
  assign w[3] = prev_block_i[159:128];
  assign w[4] = prev_block_i[127: 96];
  assign w[5] = prev_block_i[ 95: 64];
  assign w[6] = prev_block_i[ 63: 32];
  assign w[7] = prev_block_i[ 31:  0];

  // ---------- g(W[i-1]) for the (i mod 8) == 0 word --------------------------
  // RotWord: cyclic byte rotation left by 1.
  logic [31:0] rot_w7;
  assign rot_w7 = { w[7][23:0], w[7][31:24] };

  // SubWord: per-byte S-box.
  logic [31:0] sub_rot_w7;
  aes_sbox u_g0 (.in_i(rot_w7[31:24]), .out_o(sub_rot_w7[31:24]));
  aes_sbox u_g1 (.in_i(rot_w7[23:16]), .out_o(sub_rot_w7[23:16]));
  aes_sbox u_g2 (.in_i(rot_w7[15: 8]), .out_o(sub_rot_w7[15: 8]));
  aes_sbox u_g3 (.in_i(rot_w7[ 7: 0]), .out_o(sub_rot_w7[ 7: 0]));

  // XOR with Rcon (only top byte is non-zero per FIPS-197 Appendix A.3).
  logic [31:0] g_w7;
  assign g_w7 = sub_rot_w7 ^ { rcon_i, 24'h0 };

  // ---------- Compute the new 8 words ----------------------------------------
  // nw0..nw7 correspond to W[i .. i+7]. Dependencies:
  //   nw0 = w[0] ^ g(w[7])
  //   nw1 = w[1] ^ nw0
  //   nw2 = w[2] ^ nw1
  //   nw3 = w[3] ^ nw2
  //   nw4 = w[4] ^ SubWord(nw3)         <- AES-256 quirk
  //   nw5 = w[5] ^ nw4
  //   nw6 = w[6] ^ nw5
  //   nw7 = w[7] ^ nw6
  // Kept as individual scalar nets (rather than an unpacked array) so that
  // the simulator UNOPTFLAT check sees the dependency chain clearly.
  logic [31:0] nw0, nw1, nw2, nw3, nw4, nw5, nw6, nw7;

  // Plain SubWord on nw3 for the (i mod 8) == 4 word. AES-256-specific:
  // every fourth word inside an 8-word slab passes through SubWord without
  // rotation or Rcon. Collapses to no-op for AES-128.
  logic [31:0] sub_nw3;
  aes_sbox u_h0 (.in_i(nw3[31:24]), .out_o(sub_nw3[31:24]));
  aes_sbox u_h1 (.in_i(nw3[23:16]), .out_o(sub_nw3[23:16]));
  aes_sbox u_h2 (.in_i(nw3[15: 8]), .out_o(sub_nw3[15: 8]));
  aes_sbox u_h3 (.in_i(nw3[ 7: 0]), .out_o(sub_nw3[ 7: 0]));

  assign nw0 = w[0] ^ g_w7;
  assign nw1 = w[1] ^ nw0;
  assign nw2 = w[2] ^ nw1;
  assign nw3 = w[3] ^ nw2;
  assign nw4 = w[4] ^ sub_nw3;
  assign nw5 = w[5] ^ nw4;
  assign nw6 = w[6] ^ nw5;
  assign nw7 = w[7] ^ nw6;

  assign next_block_o = { nw0, nw1, nw2, nw3, nw4, nw5, nw6, nw7 };

endmodule
