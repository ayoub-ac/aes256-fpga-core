// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// Top-level testbench wrapper for aes256_core. Stimulus is driven from the C++
// harness (tb/sim_main.cpp); this module re-exports the DUT ports and binds:
//   * tb/aes256_core_assertions.sv  -- SVA protocol checks
//   * tb/aes256_core_cov.sv         -- functional coverage collector

module aes256_core_tb (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic [255:0] key_i,
  input  logic [127:0] data_i,
  input  logic         encrypt_i,
  input  logic         valid_i,
  output logic         ready_o,
  output logic [127:0] data_o,
  output logic         valid_o,
  input  logic         ready_i
);

  aes256_core u_dut (
    .clk_i     (clk_i),
    .rst_ni    (rst_ni),
    .key_i     (key_i),
    .data_i    (data_i),
    .encrypt_i (encrypt_i),
    .valid_i   (valid_i),
    .ready_o   (ready_o),
    .data_o    (data_o),
    .valid_o   (valid_o),
    .ready_i   (ready_i)
  );

  // Hierarchical references into the DUT for assertion / coverage observation.
  // These signals do not need to be at the module's port boundary.
  wire [3:0] dut_round_q = u_dut.round_q;
  wire [1:0] dut_state_q = u_dut.state_q;

  aes256_core_assertions u_assert (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),
    .valid_i (valid_i),
    .ready_o (ready_o),
    .valid_o (valid_o),
    .ready_i (ready_i),
    .data_o  (data_o),
    .round_q (dut_round_q)
  );

  aes256_core_cov u_cov (
    .clk_i     (clk_i),
    .rst_ni    (rst_ni),
    .valid_i   (valid_i),
    .ready_o   (ready_o),
    .valid_o   (valid_o),
    .ready_i   (ready_i),
    .encrypt_i (encrypt_i),
    .key_i     (key_i),
    .state_q   (dut_state_q)
  );

endmodule
