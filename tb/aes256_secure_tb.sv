// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
// Testbench wrapper for aes256_core_secure (Verilator C++ harness drives stimulus).

module aes256_secure_tb (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic [255:0] key_i,
  input  logic [127:0] data_i,
  input  logic         encrypt_i,
  input  logic         valid_i,
  input  logic [127:0] random_i,
  output logic         ready_o,
  output logic [127:0] data_o,
  output logic         valid_o,
  output logic         fault_o,
  input  logic         ready_i
);

  aes256_core_secure u_dut (
    .clk_i     (clk_i),
    .rst_ni    (rst_ni),
    .key_i     (key_i),
    .data_i    (data_i),
    .encrypt_i (encrypt_i),
    .valid_i   (valid_i),
    .random_i  (random_i),
    .ready_o   (ready_o),
    .data_o    (data_o),
    .valid_o   (valid_o),
    .fault_o   (fault_o),
    .ready_i   (ready_i)
  );

endmodule
