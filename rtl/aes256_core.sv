// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// AES-256 iterative core (FIPS-197).
//
// Algorithm parameters (FIPS-197 Table 2):
//   Block size  : 128 bits
//   Key size    : 256 bits  (Nk = 8)
//   Rounds      : 14        (Nr = 14)
//   Schedule    : 60 32-bit words = 15 x 128-bit round keys
//
// Architecture: 1 round per cycle, shared encrypt/decrypt datapath.
// Latency: ~24 cycles per block typical (7 expansion cycles + 14 round
//          cycles + FSM transitions). Throughput: 1 block / ~24 cycles.
//
// Resource shape: 15 round keys * 128 bits = 1920 FF for the schedule storage,
// dominating area. Round logic itself is identical to AES-128 (16 forward
// S-boxes + 16 inverse S-boxes + MixColumns/InvMixColumns).
//
// Handshake (AXI-Stream-like valid/ready):
//   * Master presents key_i (256 bits), data_i, encrypt_i, asserts valid_i.
//   * Core captures when (valid_i && ready_o), drops ready_o, runs.
//   * Core asserts valid_o with data_o on completion. Master pulses ready_i.
//
// Reset: rst_ni is active-low synchronous (sampled on rising clk_i edge).

module aes256_core (
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

  // ---------- Round constants (FIPS-197 Appendix A.3) ------------------------
  // AES-256 uses rc[1..7] only; expansion produces W[56..59] = rk[14] at step 7.
  function automatic logic [7:0] rcon (input logic [3:0] step);
    case (step)
      4'd1: rcon = 8'h01;
      4'd2: rcon = 8'h02;
      4'd3: rcon = 8'h04;
      4'd4: rcon = 8'h08;
      4'd5: rcon = 8'h10;
      4'd6: rcon = 8'h20;
      4'd7: rcon = 8'h40;
      default: rcon = 8'h00;
    endcase
  endfunction

  // ---------- FSM ------------------------------------------------------------
  typedef enum logic [1:0] {
    S_IDLE   = 2'd0,
    S_EXPAND = 2'd1,  // 7 cycles, building rk[2..14]
    S_RUN    = 2'd2,  // 14 cycles, cipher rounds
    S_DONE   = 2'd3
  } state_e;

  state_e state_q, state_d;

  // exp_step counts 1..7 in S_EXPAND (the index of the next slab to compute).
  // round counts 0..13 in S_RUN (number of completed forward/inverse rounds).
  logic [3:0]   exp_step_q,   exp_step_d;
  logic [3:0]   round_q,      round_d;
  logic         encrypt_q;
  logic [127:0] state_reg_q,  state_reg_d;
  logic [127:0] data_out_q,   data_out_d;

  // Round-key storage: 15 x 128 bits (rk[0] .. rk[14]).
  logic [127:0] rk_q [0:14];
  logic [127:0] rk_d [0:14];

  // ---------- Key-expansion combinational ------------------------------------
  // Each step consumes the previous 256-bit slab (two adjacent round keys) and
  // produces the next 256-bit slab. For step k (k = 1..7) the input slab is
  // rk[2k-2] || rk[2k-1] and the output slab is W[8k..8k+7], i.e. rk[2k] || rk[2k+1].
  logic [255:0] expand_in;
  logic [255:0] expand_out;
  // Pick the source slab from rk_q according to exp_step_q.
  // At cycle entering with exp_step_q = k we read rk_q[2k-2] || rk_q[2k-1].
  always_comb begin
    unique case (exp_step_q)
      4'd1: expand_in = { rk_q[ 0], rk_q[ 1] };
      4'd2: expand_in = { rk_q[ 2], rk_q[ 3] };
      4'd3: expand_in = { rk_q[ 4], rk_q[ 5] };
      4'd4: expand_in = { rk_q[ 6], rk_q[ 7] };
      4'd5: expand_in = { rk_q[ 8], rk_q[ 9] };
      4'd6: expand_in = { rk_q[10], rk_q[11] };
      4'd7: expand_in = { rk_q[12], rk_q[13] };
      default: expand_in = '0;
    endcase
  end

  aes_key_expand_256 u_kx (
    .prev_block_i (expand_in),
    .rcon_i       (rcon(exp_step_q)),
    .next_block_o (expand_out)
  );

  // ---------- Round combinational --------------------------------------------
  // For encrypt: round_q counts completed rounds. Apply round (round_q + 1) using
  // rk_q[round_q + 1]. Final round is round 14 (when round_q == 13).
  // For decrypt: at round_q == k (k = 0..13), apply inverse round with
  // rk_q[13 - k]. Final inverse round is when round_q == 13.
  // The initial AddRoundKey is handled in S_IDLE for encrypt and at the end of
  // S_EXPAND for decrypt (because rk[14] only exists after step 7 completes).

  logic [127:0] round_in;
  logic [127:0] round_out;
  logic [127:0] selected_rk;
  logic         is_final;

  assign round_in = state_reg_q;

  always_comb begin
    if (encrypt_q) begin
      selected_rk = rk_q[round_q + 4'd1];
      is_final    = (round_q == 4'd13);
    end else begin
      selected_rk = rk_q[4'd13 - round_q];
      is_final    = (round_q == 4'd13);
    end
  end

  aes_round u_rnd (
    .state_i       (round_in),
    .round_key_i   (selected_rk),
    .encrypt_i     (encrypt_q),
    .final_round_i (is_final),
    .state_o       (round_out)
  );

  // ---------- Outputs --------------------------------------------------------
  assign data_o  = data_out_q;
  assign valid_o = (state_q == S_DONE);
  assign ready_o = (state_q == S_IDLE);

  // ---------- FSM next-state -------------------------------------------------
  // expand_out for step 7 contains W[56..59] in the upper half (rk[14]) and
  // unused garbage in the lower half. Slice accordingly.
  logic [127:0] step7_rk14;
  assign step7_rk14 = expand_out[255:128];

  always_comb begin
    state_d     = state_q;
    exp_step_d  = exp_step_q;
    round_d     = round_q;
    state_reg_d = state_reg_q;
    data_out_d  = data_out_q;
    for (int i = 0; i < 15; i++) rk_d[i] = rk_q[i];

    unique case (state_q)
      S_IDLE: begin
        if (valid_i) begin
          // Load cipher key as rk[0] (W[0..3]) and rk[1] (W[4..7]).
          rk_d[0] = key_i[255:128];
          rk_d[1] = key_i[127:  0];
          for (int i = 2; i < 15; i++) rk_d[i] = '0;

          if (encrypt_i) begin
            // Initial AddRoundKey with rk[0] = upper half of cipher key.
            state_reg_d = data_i ^ key_i[255:128];
          end else begin
            // For decrypt the first AddRoundKey uses rk[14], which we do not
            // have until S_EXPAND finishes step 7. Hold the ciphertext and
            // apply rk[14] at end of S_EXPAND.
            state_reg_d = data_i;
          end
          exp_step_d = 4'd1;
          round_d    = 4'd0;
          state_d    = S_EXPAND;
        end
      end

      S_EXPAND: begin
        // Step k produces rk[2k] || rk[2k+1] (lower-half-only on step 7).
        unique case (exp_step_q)
          4'd1: begin rk_d[ 2] = expand_out[255:128]; rk_d[ 3] = expand_out[127:0]; end
          4'd2: begin rk_d[ 4] = expand_out[255:128]; rk_d[ 5] = expand_out[127:0]; end
          4'd3: begin rk_d[ 6] = expand_out[255:128]; rk_d[ 7] = expand_out[127:0]; end
          4'd4: begin rk_d[ 8] = expand_out[255:128]; rk_d[ 9] = expand_out[127:0]; end
          4'd5: begin rk_d[10] = expand_out[255:128]; rk_d[11] = expand_out[127:0]; end
          4'd6: begin rk_d[12] = expand_out[255:128]; rk_d[13] = expand_out[127:0]; end
          4'd7: begin rk_d[14] = step7_rk14; end
          default: ;
        endcase

        if (exp_step_q == 4'd7) begin
          // Schedule complete. For decrypt: do initial AddRoundKey using
          // step7_rk14 directly (rk_q[14] is not committed until next clock).
          if (!encrypt_q) begin
            state_reg_d = state_reg_q ^ step7_rk14;
          end
          exp_step_d = 4'd0;
          round_d    = 4'd0;
          state_d    = S_RUN;
        end else begin
          exp_step_d = exp_step_q + 4'd1;
        end
      end

      S_RUN: begin
        state_reg_d = round_out;
        if (round_q == 4'd13) begin
          data_out_d = round_out;
          round_d    = 4'd0;
          state_d    = S_DONE;
        end else begin
          round_d = round_q + 4'd1;
        end
      end

      S_DONE: begin
        if (ready_i) begin
          state_d = S_IDLE;
        end
      end

      default: state_d = S_IDLE;
    endcase
  end

  // ---------- Sequential -----------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      state_q     <= S_IDLE;
      exp_step_q  <= 4'd0;
      round_q     <= 4'd0;
      encrypt_q   <= 1'b0;
      state_reg_q <= '0;
      data_out_q  <= '0;
      for (int i = 0; i < 15; i++) rk_q[i] <= '0;
    end else begin
      state_q     <= state_d;
      exp_step_q  <= exp_step_d;
      round_q     <= round_d;
      state_reg_q <= state_reg_d;
      data_out_q  <= data_out_d;
      for (int i = 0; i < 15; i++) rk_q[i] <= rk_d[i];
      if (state_q == S_IDLE && valid_i) encrypt_q <= encrypt_i;
    end
  end

endmodule
