# aes256-fpga-core

[![License: GPL-3.0-or-later or commercial](https://img.shields.io/badge/license-GPL--3.0%20%7C%20commercial-blue.svg)](LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#verification)
[![FIPS-197 vectors](https://img.shields.io/badge/FIPS--197-NIST%20vectors-blue.svg)](#verification)
[![Lint](https://img.shields.io/badge/Verilator%20lint-clean-brightgreen.svg)](#build--test)

A small, synthesisable AES-256 IP core in SystemVerilog. One round per cycle,
encrypt and decrypt sharing the same datapath, single clock domain. Targets
iCE40, ECP5, Xilinx 7-series, Cyclone V, and Tang Nano 9K.

The core is a clean implementation of FIPS-197 verified end-to-end against
NIST FIPS-197 / SP 800-38A test vectors with the open-source Verilator
simulator. No FPGA hardware required for the test suite.

## Why this exists

AES-128 is fine for almost every use that picks AES at all; the
[aes128-fpga-core](https://github.com/ayoubac/aes128-fpga-core) sister project
covers that case. The moment a compliance team is involved — FIPS 140-3
modules, GDPR-sensitive payloads, banking, healthcare, government-adjacent
integrators — the spec line item often reads "AES with a 256-bit key" and
nothing else will do. This core fills that slot, with a clean dual license,
a real handshake protocol, NIST vectors in the testbench, SystemVerilog
assertions, functional coverage, and a synthesis-comparison report across
multiple toolchains.

## Quickstart

```bash
git clone https://github.com/ayoubac/aes256-fpga-core.git
cd aes256-fpga-core
make lint test            # Verilator lint + run NIST vector tests
make synth_report         # SYNTH_REPORT.md across iCE40/ECP5/Xilinx/Vivado/Quartus
```

Requires Verilator 5.0+ for simulation. Yosys 0.30+ for the open synth flow.

## Architecture

```
                  +-----------------+
       key_i ---->|                 |
      data_i ---->|   aes256_core   |----> data_o
   encrypt_i ---->|  (FSM + round)  |
     valid_i ---->| ready_o valid_o |----> valid_o
     ready_i ---->|                 |----> ready_o
                  +--------+--------+
                           |
              +------------+------------+
              |            |            |
        aes_key_expand_256 aes_round  aes_sbox /
        (1 slab/cycle)    (combo)    aes_inv_sbox
                                     (LUT)
```

FSM: `IDLE -> EXPAND (7c) -> RUN (14c) -> DONE -> IDLE`. AES-256 has a
2-key-per-step expansion (Nk = 8), so 7 expand cycles produce all 15 round
keys; the 14 cipher rounds run over the next 14 cycles. Latency: 23 cycles
per block in the basic core. The pipelined variant achieves one block per
cycle steady-state after a 15-cycle fill.

## Port table

| Signal      | Dir | Width | Description                                                                                                                       | FIPS-197 ref |
|-------------|-----|-------|-----------------------------------------------------------------------------------------------------------------------------------|--------------|
| `clk_i`     | in  | 1     | System clock. All flops sample on the rising edge.                                                                                | -            |
| `rst_ni`    | in  | 1     | Synchronous active-low reset. Hold low ≥4 cycles before first command.                                                            | -            |
| `key_i`     | in  | 256   | AES-256 cipher key. Byte 0 in bits [255:248].                                                                                     | §5.2         |
| `data_i`    | in  | 128   | Plaintext (when `encrypt_i=1`) or ciphertext (when `encrypt_i=0`).                                                                | §5.1 / §5.3  |
| `encrypt_i` | in  | 1     | Mode select. 1 = encrypt, 0 = decrypt.                                                                                            | §5           |
| `valid_i`   | in  | 1     | Master asserts when key/data are valid. Transfer accepted on `valid_i && ready_o`.                                                | -            |
| `ready_o`   | out | 1     | Core ready to accept a new block.                                                                                                 | -            |
| `data_o`    | out | 128   | Output ciphertext or plaintext. Stable while `valid_o` is asserted.                                                               | -            |
| `valid_o`   | out | 1     | Core has produced a result.                                                                                                       | -            |
| `ready_i`   | in  | 1     | Master asserts to consume the output.                                                                                             | -            |

See [`PORT_DESCRIPTION.md`](PORT_DESCRIPTION.md) for the full handshake
protocol with timing diagrams.

## Headline numbers

Real numbers from `make synth_report` (Yosys 0.33, basic iterative core):

| Target           | LUT          | FF   | BRAM | Latency    | Throughput @ Fmax     |
|------------------|--------------|------|------|------------|-----------------------|
| iCE40 UP5K       | 8521 SB_LUT4 | 2189 | 32   | 23 cycles  | ~278 Mbps @ 50 MHz    |
| ECP5 LFE5UM-25   | 18985 LUT4*  | 2445 | 0    | 23 cycles  | ~668 Mbps @ 120 MHz   |
| Xilinx Artix-7   | 2461 LUT     | 2189 | 0    | 23 cycles  | ~835 Mbps @ 150 MHz   |

\* ECP5 generic synth with Yosys does not infer distributed RAM for the
round-key bank; `nextpnr-ecp5` packing reduces this 4-5x.
See [`RESOURCE_ESTIMATES.md`](RESOURCE_ESTIMATES.md) for the full breakdown.

## Build & test

You need [Verilator](https://verilator.org/) 5.0 or newer.

```bash
make lint          # static check the RTL (basic + secure + pipelined)
make test          # build and run NIST vector test suite
make test-secure   # build and run secure-variant test suite
make test-all      # run both
```

A passing run ends with `+PASS all tests passed` and exits 0.

## Verification

Three orthogonal techniques are wired into the testbench:

### Directed tests (10 groups)

| # | Test                                  | Coverage                                     |
|---|---------------------------------------|----------------------------------------------|
| 1 | NIST vectors, encrypt                 | FIPS-197 App.C.3, NIST SP 800-38A F.1.5      |
| 2 | NIST vectors, decrypt                 | Same vectors run backwards                   |
| 3 | `decrypt(encrypt(x)) == x`            | Round-trip on edge plaintexts                |
| 4 | Back-to-back throughput               | 16 blocks, observes ~23 cycles/block         |
| 5 | Edge-case known vectors               | All-zero, all-FF, single-bit                 |
| 6 | 1000 random round-trips               | Statistical sanity                           |
| 7 | Back-to-back with key changes         | Schedule re-expansion correctness            |
| 8 | Reset asserted mid-operation          | FSM recovery to IDLE                         |
| 9 | Long stall with `ready_i` low         | Back-pressure / `data_o` stability           |
|10 | Cross-validate vs pycryptodome        | 100 random keys/plaintexts                   |

### SystemVerilog assertions

`tb/aes256_core_assertions.sv` enforces protocol invariants on every cycle of
every test:

- `valid_o` cannot rise sooner than 15 cycles after an accepted command
- `data_o` is stable while back-pressured (`valid_o && !ready_i`)
- `valid_o` is held until `ready_i` is observed
- The round counter never exceeds 14
- `ready_o` and `valid_o` are mutually exclusive

The assertions compile with both Verilator 5.x (`--assert`) and Vivado
xsim. They are stripped on synthesis flows via `` `ifndef SYNTHESIS ``.

### Functional coverage

`tb/aes256_core_cov.sv` collects nine bins. The simulator prints a
coverage summary at end-of-test:

```
---- Functional coverage ----
  [HIT ] state_idle / state_expand / state_run / state_done
  [HIT ] encrypt_path / decrypt_path
  [HIT ] back_pressure / key_change / reset_mid_op
Coverage: 9/9 bins (100.0%)
```

A regression that drops below 100% fails the gate.

### Synthesis comparison report

`make synth_report` runs every available toolchain on the same RTL and
emits [`SYNTH_REPORT.md`](SYNTH_REPORT.md) with a side-by-side LUT/FF/BRAM
table. Yosys (`synth_ice40` / `synth_ecp5` / `synth_xilinx`) is mandatory;
Vivado and Quartus are detected automatically and skipped with a notice
when not on `$PATH`.

## Variants

| Variant                            | Use case                                                                                                  | Tier    |
|------------------------------------|-----------------------------------------------------------------------------------------------------------|---------|
| `rtl/aes256_core.sv`               | Default: 23-cycle iterative core, encrypt + decrypt                                                       | GPL     |
| `rtl/aes256_core_pipelined.sv`     | Fully unrolled, ~14x throughput at ~5x area, encrypt-only                                                 | Premium |
| `rtl/aes256_core_secure.sv`        | Boolean masking + duplicated round counter + constant-time FSM. See [`SECURITY.md`](SECURITY.md).         | Premium |
| `vhdl_wrapper/aes256_core_vhdl.vhd` | VHDL-2008 entity wrapping the SV core for VHDL-only designs                                              | All     |

## License

Dual-licensed:

- **GPL-3.0-or-later** for open-source projects. If your product links this
  RTL or its compiled bitstream, your project must also be GPL-3.0+.
- **Commercial license** for closed-source products. Tiers and pricing in
  [`PRICING.md`](PRICING.md). See [`LICENSE.md`](LICENSE.md) for the legal
  text and an FAQ.

If unsure which applies, read `LICENSE.md` or open an issue.

## Repository layout

```
rtl/                       RTL sources
  aes256_core.sv             top-level basic core, FSM, round-key store
  aes256_core_pipelined.sv   fully unrolled variant
  aes256_core_secure.sv      SCA-hardened variant
  aes_round.sv               combinational SubBytes/ShiftRows/MixColumns + inverses
  aes_key_expand_256.sv      one-step AES-256 key expansion (8 words/cycle)
  aes_sbox.sv                forward S-box LUT (FIPS-197 Fig. 7)
  aes_inv_sbox.sv            inverse S-box LUT (FIPS-197 Fig. 14)
tb/                        testbench
  sim_main.cpp               C++ harness, NIST vectors, 10 test groups
  sim_secure.cpp             secure-variant tests (mask invariance, fault inj.)
  aes256_core_tb.sv          DUT wrapper + assertion + coverage instantiation
  aes256_core_assertions.sv  SVA properties
  aes256_core_cov.sv         functional coverage collector
  aes256_secure_tb.sv        DUT wrapper for secure variant
  nist_vectors.sv            same vectors in SV (for non-Verilator simulators)
  random_vectors.h           generated cross-validation vectors (pycryptodome)
vhdl_wrapper/              VHDL-2008 wrapper for mixed-language designs
scripts/                   helper scripts (synth_report.sh, vhdl_cosim.sh)
Makefile                   build/lint/sim/synth/synth_report/vhdl-test
```

## Contributing

Bug reports and patches welcome. Process:

1. File an issue first for non-trivial changes.
2. Fork, branch, and run `make lint test test-secure` locally.
3. Open a pull request with a description of what changed and why.
4. CI runs the full test suite plus `synth_report`; both must be green.

## Citation

```bibtex
@misc{aes256-fpga-core,
  title  = {{aes256-fpga-core}: a small dual-licensed AES-256 IP core in SystemVerilog},
  author = {Achour, Ayoub},
  year   = {2026},
  howpublished = {\url{https://github.com/ayoubac/aes256-fpga-core}}
}
```

## References

- NIST FIPS-197, *Advanced Encryption Standard*, November 2001 — especially
  §5.1 (Cipher), §5.2 (KeyExpansion), §5.3 (InvCipher), and Appendix C.3
  (AES-256 known-answer vector).
- NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation*,
  Appendix F.1.5 / F.1.6 (ECB-AES256).
- E. Trichina, *Combinational Logic Design for AES SubByte Transformation
  on Masked Data*, IACR ePrint 2003/236.

## Author

Ayoub Achour - [github.com/ayoubac](https://github.com/ayoubac)
