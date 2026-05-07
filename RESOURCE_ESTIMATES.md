# Resource estimates

Numbers below are from Yosys 0.33 generic synthesis (`make synth_report`).
They are pre-place-and-route, so the vendor flow (nextpnr / Vivado / Diamond)
will usually pack tighter, especially on iCE40 where SB_LUT4 + carry chains
and BRAM packing reduce visible LUT count after PnR. Run `make synth_report`
for authoritative numbers on your toolchain version.

## Summary (post-Yosys 0.33 generic, pre-PnR)

| Target                         | LUT (logic)   | FF       | RAM            |
|--------------------------------|---------------|----------|----------------|
| Lattice iCE40 UP5K             | 8521 SB_LUT4  | 2189 FF  | 32 SB_RAM40_4K |
| Lattice ECP5 LFE5UM-25         | 18985 LUT4    | 2445 FF  | 0              |
| Xilinx Artix-7 XC7A35T         | 2461 LUT      | 2189 FF  | 0              |

These numbers cover the iterative MVP and were produced by `make synth_report`
against this tree. The same target writes `SYNTH_REPORT.md` with all the
detected toolchains in one table; rerun for authoritative numbers on your
toolchain version.

The iCE40 number is shaped by the BRAM inference for the 15 x 128-bit
round-key bank; on ECP5 the same bank is built out of distributed mux logic
in Yosys 0.33's `synth_ecp5`, which is the source of the inflated LUT4 count.
Expect the ECP5 footprint to drop sharply after `nextpnr-ecp5` packing or by
adding an explicit `(* ram_style = "distributed" *)` attribute on `rk_q`. On
Xilinx, Vivado will pack the schedule into SLICEM distributed RAM and the
post-Vivado LUT count is typically ~1.5k-2.0k LUT6.

## Cycles per block

| Phase | Cycles | Notes |
|-------|--------|-------|
| Key expansion | 7 | One slab (256 bits = 2 round keys) per cycle. |
| Cipher rounds | 14 | One round per cycle. |
| FSM transitions | 2 | IDLE -> EXPAND, RUN -> DONE. |
| **Total per block** | **23** | Verified by the back-to-back test (`Test 4`). |

For a stream with a stable key, the Premium key-cached variant skips
re-expansion and reaches ~16 cycles per block.

## Variants (Premium tier)

Both Premium variants share the same `aes_round` / `aes_sbox` infrastructure
as the basic core, so the deltas below are RTL-overhead only.

### Pipelined (`aes256_core_pipelined`)

| Target          | LUT (Yosys)        | FF       | Throughput                                   |
|-----------------|--------------------|----------|----------------------------------------------|
| Xilinx 7-series | ~32k LUT total     | ~5.0k FF | 1 block/cycle steady-state (~14x basic)      |

Trade-off: ~5x area for ~14x throughput. Encrypt-only; decrypt falls back to
the iterative core. Schedule re-expansion is amortized by holding `ready_o`
low during the 7-cycle expansion, so a stable key sees no per-block overhead.

### Secure (`aes256_core_secure`)

| Target          | LUT (Yosys)        | FF       | Cycles/block | Throughput            |
|-----------------|--------------------|----------|--------------|-----------------------|
| Xilinx 7-series | ~2.7k LUT total    | ~2.4k FF | 23 (same as basic) | ~835 Mbps @ 150 MHz |

Adds ~7-8% area for state-level Boolean masking (128-bit mask register +
shadow), duplicated round counter (fault detector), and constant-time FSM.
See `SECURITY.md` for the full threat model. Throughput is unchanged.

## What dominates the area

- **15 round keys * 128 bits = 1920 FFs** for storing the expanded key
  schedule. By far the largest FF cost. The key-cached variant keeps this
  and skips re-expansion when the key does not change.
- **Two S-box LUTs** (forward and inverse) per byte lane in the round logic.
  The round instantiates 16 forward S-boxes (SubBytes) and 16 inverse
  S-boxes (InvSubBytes). The key expansion adds eight more forward S-boxes
  per step (four for `g` and four for the AES-256 mid-slab `h`). Future
  area optimization: share S-boxes across encrypt/decrypt by switching the
  lookup table.
- **MixColumns / InvMixColumns** combinational matrix. InvMixColumns
  coefficients {0x09, 0x0b, 0x0d, 0x0e} are decomposed into nested `xtime`
  chains with shared `2a, 4a, 8a` per byte, which Yosys maps to ~2-3 LUTs
  per coefficient byte rather than a generic GF(2^8) multiplier loop.

## What you can do to shrink it

- For very small iCE40 devices, ask about the Premium "byte-serial" build —
  one column per cycle, ~3x smaller LUT count, 4x more cycles per block.
- The 256-bit key port is by far the widest input. If you use a single fixed
  key, you can const-prop the key into the schedule storage at synthesis time
  and remove most of the expansion logic. Ask if you need this hardened drop.

## Frequency

- iCE40 UP5K, default toolchain (Yosys + nextpnr), no constraints: ~50 MHz typical.
- ECP5: ~120 MHz typical.
- Artix-7 -1 speed grade: ~150 MHz typical, ~200 MHz with effort and timing constraints.

The combinational path through SubBytes -> ShiftRows -> MixColumns ->
AddRoundKey is the critical path. Retiming the round-key XOR into the next
stage's flop helps on Xilinx; on Yosys+nextpnr you may want to split
MixColumns over two cycles for higher Fmax (this is one of the Premium
variants).

## Power

Roughly 6-18 mW dynamic on iCE40 UP5K at 50 MHz, depending on data activity.
Slightly higher than the AES-128 sibling because of the larger key schedule
storage and the extra 4 round cycles. Static power is dominated by the FPGA
itself.

## How to reproduce

```bash
make synth_report   # cross-toolchain report
make synth          # individual ice40 / ecp5 / xilinx logs
```

`make synth_report` runs Yosys against every available toolchain and writes
`SYNTH_REPORT.md` with a side-by-side table. `make synth` produces
per-target raw stats logs in `synth_*.log`. The stats line at the bottom
tells you cell counts per primitive.

For end-to-end place-and-route numbers (post-PnR LUT counts and timing), run
the vendor flow:
- iCE40 / ECP5: nextpnr-ice40 / nextpnr-ecp5 with Yosys output (open toolchain).
- Xilinx: Vivado with a project pointing at the `rtl/` files.
- Lattice Diamond / Radiant: project with `rtl/` added.
