// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// Functional coverage collector for aes256_core. Counts hits on the bins below
// from C++ via Verilator's --public-flat-rw, so the harness can read them at
// the end of the simulation and print a coverage percentage.
//
// Bins:
//   c_state_idle       FSM in S_IDLE at least once
//   c_state_expand     FSM in S_EXPAND at least once
//   c_state_run        FSM in S_RUN at least once
//   c_state_done       FSM in S_DONE at least once
//   c_encrypt_path     a block was processed with encrypt_i = 1
//   c_decrypt_path     a block was processed with encrypt_i = 0
//   c_back_pressure    valid_o held high for >=2 cycles before ready_i
//   c_key_change       a new key arrived back-to-back (different from the
//                      previously accepted key)
//   c_reset_mid_op     reset asserted while state != IDLE
//
// Total: 9 bins. Coverage % = hits / 9 * 100.

module aes256_core_cov (
  input logic         clk_i,
  input logic         rst_ni,
  input logic         valid_i,
  input logic         ready_o,
  input logic         valid_o,
  input logic         ready_i,
  input logic         encrypt_i,
  input logic [255:0] key_i,
  input logic [1:0]   state_q
);

  localparam logic [1:0] L_IDLE   = 2'd0;
  localparam logic [1:0] L_EXPAND = 2'd1;
  localparam logic [1:0] L_RUN    = 2'd2;
  localparam logic [1:0] L_DONE   = 2'd3;

  // Public coverage flags. /*verilator public*/ exposes them to the C++ side.
  logic c_state_idle    /*verilator public*/;
  logic c_state_expand  /*verilator public*/;
  logic c_state_run     /*verilator public*/;
  logic c_state_done    /*verilator public*/;
  logic c_encrypt_path  /*verilator public*/;
  logic c_decrypt_path  /*verilator public*/;
  logic c_back_pressure /*verilator public*/;
  logic c_key_change    /*verilator public*/;
  logic c_reset_mid_op  /*verilator public*/;

  // Track previous key to detect back-to-back key change.
  logic [255:0] prev_key_q;
  logic         prev_key_valid_q;

  // Track valid_o history for back-pressure detection.
  logic prev_valid_o_q;

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      // Reset asserted: if the FSM was busy the cycle before, count it as a
      // mid-operation reset. Coverage flags themselves are NOT cleared - they
      // are sticky for the lifetime of the simulation, so a reset between
      // tests does not erase prior bin hits.
      if (state_q != L_IDLE) c_reset_mid_op <= 1'b1;
      prev_key_q       <= '0;
      prev_key_valid_q <= 1'b0;
      prev_valid_o_q   <= 1'b0;
    end else begin
      // FSM state coverage
      if (state_q == L_IDLE)   c_state_idle   <= 1'b1;
      if (state_q == L_EXPAND) c_state_expand <= 1'b1;
      if (state_q == L_RUN)    c_state_run    <= 1'b1;
      if (state_q == L_DONE)   c_state_done   <= 1'b1;

      // Direction coverage (sampled when a command is accepted)
      if (valid_i && ready_o) begin
        if (encrypt_i)  c_encrypt_path <= 1'b1;
        else            c_decrypt_path <= 1'b1;

        if (prev_key_valid_q && (key_i != prev_key_q)) c_key_change <= 1'b1;
        prev_key_q       <= key_i;
        prev_key_valid_q <= 1'b1;
      end

      // Back-pressure coverage: valid_o stayed high for at least one cycle
      // without ready_i being seen.
      if (prev_valid_o_q && valid_o && !ready_i) c_back_pressure <= 1'b1;
      prev_valid_o_q <= valid_o;
    end
  end

  initial begin
    c_state_idle    = 1'b0;
    c_state_expand  = 1'b0;
    c_state_run     = 1'b0;
    c_state_done    = 1'b0;
    c_encrypt_path  = 1'b0;
    c_decrypt_path  = 1'b0;
    c_back_pressure = 1'b0;
    c_key_change    = 1'b0;
    c_reset_mid_op  = 1'b0;
  end

endmodule
