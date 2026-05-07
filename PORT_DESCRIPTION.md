# Port description

This document is the contract for `aes256_core`. Bit widths, polarity, timing, and the handshake protocol.

## Module declaration

```systemverilog
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
```

## Pin-by-pin

| Signal      | Dir | Width | Description |
|-------------|-----|-------|-------------|
| `clk_i`     | in  | 1     | System clock. All flops in the core sample on the rising edge. |
| `rst_ni`    | in  | 1     | Synchronous, active-low reset. Hold low for >= 4 clocks before first valid command. |
| `key_i`     | in  | 256   | AES-256 cipher key. Sampled on the cycle that `valid_i && ready_o`. Endianness: bit 255 is the most-significant bit of byte 0 of the 32-byte key, matching FIPS-197 convention. |
| `data_i`    | in  | 128   | Plaintext (when `encrypt_i=1`) or ciphertext (when `encrypt_i=0`). Same endianness as `key_i`: bit 127 is the most-significant bit of byte 0 of the 16-byte block. |
| `encrypt_i` | in  | 1     | Mode select. `1` = encrypt `data_i` to ciphertext. `0` = decrypt `data_i` to plaintext. Sampled with `valid_i`. |
| `valid_i`   | in  | 1     | Master asserts when key/data are valid. Asserting when `ready_o == 0` is allowed but the transfer does not complete until `ready_o` rises. |
| `ready_o`   | out | 1     | Core ready to accept a new block. `valid_i && ready_o` = transfer accepted. |
| `data_o`    | out | 128   | Output ciphertext or plaintext. Stable while `valid_o` is asserted. Same endianness as `data_i`. |
| `valid_o`   | out | 1     | Core has produced a result. Master must observe `valid_o` and assert `ready_i` to consume. |
| `ready_i`   | in  | 1     | Master asserts to consume the output. The core advances to its idle state on the cycle after `valid_o && ready_i`. |

## Handshake

The core uses the same valid/ready pattern as AXI-Stream:

- A transfer happens on a rising clock edge where the asserting party has its `valid` high and the receiving party has its `ready` high.
- Either side may stall by deasserting its half of the handshake.

### Input handshake (master -> core)

```
clk         _|‾|_|‾|_|‾|_|‾|_
ready_o    1   1   1   0   ...
valid_i    0   1   1   0   ...
key_i,
data_i,    -   K   K   -
encrypt_i

           ^ here master drives K and asserts valid_i; core's ready_o is also high,
             so the transfer is accepted on this rising edge. The core lowers
             ready_o and starts processing.
```

### Output handshake (core -> master)

```
clk         _|‾|_|‾|_|‾|_|‾|_
valid_o    0   1   1   0   ...
ready_i    -   0   1   -   ...
data_o     -   D   D   -

           ^ core asserts valid_o with data; master eventually asserts
             ready_i; transfer happens; core returns to idle.
```

## Timing

- **Latency**: from the cycle `valid_i && ready_o` is captured to the cycle `valid_o` rises is approximately 23 cycles in this MVP (7 expansion cycles + 14 round cycles + FSM transitions). Verified at exactly 23 cycles per block in the back-to-back throughput test.
- **Throughput**: one block per ~23 cycles. At 50 MHz that is ~278 Mbps; at 100 MHz, ~556 Mbps.
- **Back-to-back**: yes — the master can present a new `(key, data)` on the same cycle it consumes the previous output (`valid_o && ready_i` and immediately `valid_i` for the next block).

For a steady stream where the key does not change, the Premium key-cached variant skips the 7-cycle expansion to reach ~16 cycles per block.

## Reset

- `rst_ni` is **synchronous**, **active-low**.
- Drive `rst_ni = 0` for at least four `clk_i` rising edges before the first command.
- During reset all output signals are low, all internal state is cleared. The previously stored key is wiped — issue a fresh key on the next command.

## Endianness clarification

A 256-bit AES key is conventionally written as 32 bytes in left-to-right order. We adopt the FIPS-197 convention: byte 0 (the leftmost byte of the standard hex string) is in bits `[255:248]`, byte 31 (the rightmost) is in bits `[7:0]`.

Example (FIPS-197 Appendix C.3):
```
key       = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
              ^^                                                           ^^
              byte 0 -> bits [255:248]                       byte 31 -> bits [7:0]

plaintext = 0x00112233445566778899aabbccddeeff
              ^^                           ^^
              byte 0 -> bits [127:120]     byte 15 -> bits [7:0]
```

If your bus is little-endian, you must swap bytes before driving `key_i` and `data_i`.

## Clock domain

Single clock domain. `clk_i` clocks every flop in the design. If your system is multi-clock, instantiate this core in its own domain and use a CDC FIFO on `data_i` / `data_o` and a one-shot synchronizer on `key_i`.

## Synthesis attributes

The core uses no vendor-specific attributes. It synthesizes cleanly with Yosys (`synth_ice40`, `synth_ecp5`, `synth_xilinx`) and with Vivado (default flow).

The S-box and inverse-S-box are written as `case` statements; Yosys infers a LUT, Vivado infers either LUTs or a distributed-RAM ROM depending on the device.
