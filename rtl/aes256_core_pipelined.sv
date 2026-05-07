// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// AES-256 fully unrolled pipelined core (FIPS-197).
//
// Architecture: 15-stage pipeline (1 stage per round + initial AddRoundKey).
//   Steady-state throughput: one block per cycle.
//   Latency: 15 cycles (initial ARK + 14 rounds) plus 1 cycle for input register.
//   The key schedule is precomputed once when the key changes; while the
//   schedule is being built, valid_i is held back via ready_o (7 cycles).
//
// Trade-off: ~14x area vs the iterative core, ~14x throughput at steady state.
//
// Limitation in this build: encrypt-only. Decrypt uses the iterative core.
// (The pipelined decrypt path is symmetric but doubles the area again.)
//
// Same I/O contract as aes256_core, except:
//   * encrypt_i is ignored (always encrypt). Provided to keep the port wide-
//     compatible with the iterative core for drop-in replacement.
//   * latency is 15 cycles when key is stable; +7 cycles only on key change.

module aes256_core_pipelined (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic [255:0] key_i,
  input  logic [127:0] data_i,
  input  logic         encrypt_i,   // ignored, always encrypt
  input  logic         valid_i,
  output logic         ready_o,
  output logic [127:0] data_o,
  output logic         valid_o,
  input  logic         ready_i
);

  // unused — silence linter
  logic unused_encrypt;
  assign unused_encrypt = encrypt_i;

  // ---------- Round constants ------------------------------------------------
  function automatic logic [7:0] rcon_byte (input logic [3:0] step);
    case (step)
      4'd1: rcon_byte = 8'h01; 4'd2: rcon_byte = 8'h02; 4'd3: rcon_byte = 8'h04;
      4'd4: rcon_byte = 8'h08; 4'd5: rcon_byte = 8'h10; 4'd6: rcon_byte = 8'h20;
      4'd7: rcon_byte = 8'h40; default: rcon_byte = 8'h00;
    endcase
  endfunction

  // ---------- Round-key schedule (precomputed) -------------------------------
  // 15 round keys. When key_i changes (detected by compare to last accepted),
  // we expand all required slabs over 7 cycles and stall valid_i.
  logic [127:0] rk [0:14];
  logic [255:0] last_key_q;
  logic         schedule_ready_q;
  logic [3:0]   expand_q;     // 1..7 in progress, 0 idle

  // Combinational expansion of the slab indexed by expand_q.
  logic [255:0] kx_in, kx_out;
  always_comb begin
    unique case (expand_q)
      4'd1: kx_in = { rk[ 0], rk[ 1] };
      4'd2: kx_in = { rk[ 2], rk[ 3] };
      4'd3: kx_in = { rk[ 4], rk[ 5] };
      4'd4: kx_in = { rk[ 6], rk[ 7] };
      4'd5: kx_in = { rk[ 8], rk[ 9] };
      4'd6: kx_in = { rk[10], rk[11] };
      4'd7: kx_in = { rk[12], rk[13] };
      default: kx_in = '0;
    endcase
  end
  aes_key_expand_256 u_kx (
    .prev_block_i (kx_in),
    .rcon_i       (rcon_byte(expand_q)),
    .next_block_o (kx_out)
  );

  // ---------- Pipeline registers ---------------------------------------------
  // stage 0: input + AddRoundKey with rk[0] (registered)
  // stages 1..14: full round (registered output)
  logic [127:0] stage_q [0:14];
  logic         stage_v [0:14];

  // Combinational round outputs for stages 1..14.
  logic [127:0] round_out [1:14];
  genvar gs;
  generate
    for (gs = 1; gs <= 14; gs++) begin : g_round
      aes_round u_r (
        .state_i       (stage_q[gs-1]),
        .round_key_i   (rk[gs]),
        .encrypt_i     (1'b1),
        .final_round_i (gs == 14),
        .state_o       (round_out[gs])
      );
    end
  endgenerate

  // ---------- Output ---------------------------------------------------------
  assign data_o  = stage_q[14];
  assign valid_o = stage_v[14];
  assign ready_o = schedule_ready_q & (~stage_v[14] | ready_i);

  // ---------- Sequential -----------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      schedule_ready_q <= 1'b0;
      expand_q         <= 4'd0;
      last_key_q       <= '0;
      for (int i = 0; i <= 14; i++) begin
        rk[i]      <= '0;
        stage_q[i] <= '0;
        stage_v[i] <= 1'b0;
      end
    end else begin
      // Key schedule machine: when key changes, restart expansion.
      if (valid_i && (key_i != last_key_q) && (expand_q == 4'd0) && schedule_ready_q) begin
        rk[0]            <= key_i[255:128];
        rk[1]            <= key_i[127:  0];
        last_key_q       <= key_i;
        schedule_ready_q <= 1'b0;
        expand_q         <= 4'd1;
      end else if (!schedule_ready_q && expand_q != 4'd0) begin
        // Commit slab outputs. Step 7 only writes rk[14] (upper half of slab).
        unique case (expand_q)
          4'd1: begin rk[ 2] <= kx_out[255:128]; rk[ 3] <= kx_out[127:0]; end
          4'd2: begin rk[ 4] <= kx_out[255:128]; rk[ 5] <= kx_out[127:0]; end
          4'd3: begin rk[ 6] <= kx_out[255:128]; rk[ 7] <= kx_out[127:0]; end
          4'd4: begin rk[ 8] <= kx_out[255:128]; rk[ 9] <= kx_out[127:0]; end
          4'd5: begin rk[10] <= kx_out[255:128]; rk[11] <= kx_out[127:0]; end
          4'd6: begin rk[12] <= kx_out[255:128]; rk[13] <= kx_out[127:0]; end
          4'd7: begin rk[14] <= kx_out[255:128]; end
          default: ;
        endcase
        if (expand_q == 4'd7) begin
          schedule_ready_q <= 1'b1;
          expand_q         <= 4'd0;
        end else begin
          expand_q <= expand_q + 4'd1;
        end
      end else if (valid_i && (last_key_q == '0) && (rk[0] == '0)) begin
        // Cold-start: first key ever
        rk[0]      <= key_i[255:128];
        rk[1]      <= key_i[127:  0];
        last_key_q <= key_i;
        schedule_ready_q <= 1'b0;
        expand_q   <= 4'd1;
      end

      // Pipeline advance — only when downstream can accept (ready_i high or
      // stage 14 empty).
      if (~stage_v[14] | ready_i) begin
        // stage 0
        if (valid_i && schedule_ready_q && (key_i == last_key_q)) begin
          stage_q[0] <= data_i ^ rk[0];
          stage_v[0] <= 1'b1;
        end else begin
          stage_v[0] <= 1'b0;
        end
        // stages 1..14
        for (int i = 1; i <= 14; i++) begin
          stage_q[i] <= round_out[i];
          stage_v[i] <= stage_v[i-1];
        end
      end
    end
  end

endmodule
