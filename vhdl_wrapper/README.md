# VHDL wrapper

`aes256_core_vhdl.vhd` is a thin VHDL-2008 entity that re-exposes the
SystemVerilog `aes256_core` module under a VHDL-friendly interface. Use it from
a VHDL design that does not want to touch SystemVerilog directly.

## Status

**Wrapper only.** The cipher datapath (SubBytes, ShiftRows, MixColumns, key
schedule, FSM) lives in `rtl/*.sv` and is instantiated as a SystemVerilog
black-box. Mixed-language elaboration is supported by every commercial
simulator and synthesiser the core has been tested against.

A pure VHDL re-implementation of the cipher core is on the roadmap (Premium
tier, scope: parity with `rtl/aes256_core.sv`, including the same testbench
checks). Until then, treat this directory as a binding layer, not as a
second implementation.

## Usage

### Vivado / Quartus / Diamond

Add both the SystemVerilog files and `aes256_core_vhdl.vhd` to the same
project library (`work` is fine). The toolchain resolves the SV component
automatically:

```tcl
# Vivado
read_verilog -sv {rtl/aes_sbox.sv rtl/aes_inv_sbox.sv rtl/aes_key_expand_256.sv \
                  rtl/aes_round.sv rtl/aes256_core.sv}
read_vhdl -vhdl2008 vhdl_wrapper/aes256_core_vhdl.vhd
```

### ModelSim / Questa / Aldec

```
vlog -sv rtl/aes_sbox.sv rtl/aes_inv_sbox.sv rtl/aes_key_expand_256.sv \
        rtl/aes_round.sv rtl/aes256_core.sv
vcom -2008 vhdl_wrapper/aes256_core_vhdl.vhd
```

### GHDL + Verilator (open-source co-sim)

GHDL compiles the VHDL side, Verilator compiles the SV side, and the two are
linked through GHDL's VHPI bridge. The provided `make vhdl-test` target wraps
this; run it from the repository root:

```
make vhdl-test
```

The target is a no-op (with a notice) if `ghdl` is not on `$PATH`.

## Instantiation example

```vhdl
library ieee;
  use ieee.std_logic_1164.all;

entity my_design is end entity;
architecture rtl of my_design is
  signal clk, rstn, valid_i, ready_o, valid_o, ready_i, encrypt_i : std_logic;
  signal key_i  : std_logic_vector(255 downto 0);
  signal data_i, data_o : std_logic_vector(127 downto 0);
begin
  u_aes : entity work.aes256_core_vhdl
    port map (
      clk_i     => clk,
      rst_ni    => rstn,
      key_i     => key_i,
      data_i    => data_i,
      encrypt_i => encrypt_i,
      valid_i   => valid_i,
      ready_o   => ready_o,
      data_o    => data_o,
      valid_o   => valid_o,
      ready_i   => ready_i
    );
end architecture;
```

## What this wrapper does NOT change

* Latency, throughput, area: identical to `aes256_core.sv`. There is no
  additional pipeline stage.
* Endianness: bit 255 is byte 0 of the key; bit 127 is byte 0 of the block,
  MSB-first, exactly as documented in `PORT_DESCRIPTION.md`.
* Reset polarity: still active-low synchronous (`rst_ni`).
