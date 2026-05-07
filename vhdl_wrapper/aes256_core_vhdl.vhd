-- SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
--
-- VHDL-2008 wrapper for the SystemVerilog aes256_core module.
--
-- This entity exposes the AES-256 core's port list in VHDL syntax. The
-- architecture instantiates the SystemVerilog module by component name; mixed-
-- language elaboration is supported natively by Vivado, Quartus, ModelSim /
-- Questa, and Aldec, and via the GHDL VHPI bridge for open simulation.
--
-- Status: WRAPPER ONLY. The cipher logic itself remains in SystemVerilog
-- (rtl/*.sv). A native VHDL port of the datapath is listed as future work in
-- vhdl_wrapper/README.md.
--
-- I/O contract: identical to aes256_core.sv (see PORT_DESCRIPTION.md).
--   * Single clock, active-low synchronous reset.
--   * Valid/ready handshake on both input and output sides.
--   * 256-bit key, 128-bit data, encrypt/decrypt mode select.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

entity aes256_core_vhdl is
  port (
    clk_i     : in  std_logic;
    rst_ni    : in  std_logic;
    key_i     : in  std_logic_vector(255 downto 0);
    data_i    : in  std_logic_vector(127 downto 0);
    encrypt_i : in  std_logic;
    valid_i   : in  std_logic;
    ready_o   : out std_logic;
    data_o    : out std_logic_vector(127 downto 0);
    valid_o   : out std_logic;
    ready_i   : in  std_logic
  );
end entity aes256_core_vhdl;

architecture rtl of aes256_core_vhdl is

  -- Forward declaration of the SystemVerilog component. Tools resolve this by
  -- name at elaboration; the SystemVerilog source must be added to the same
  -- compilation library (work) before the VHDL elaboration step.
  component aes256_core
    port (
      clk_i     : in  std_logic;
      rst_ni    : in  std_logic;
      key_i     : in  std_logic_vector(255 downto 0);
      data_i    : in  std_logic_vector(127 downto 0);
      encrypt_i : in  std_logic;
      valid_i   : in  std_logic;
      ready_o   : out std_logic;
      data_o    : out std_logic_vector(127 downto 0);
      valid_o   : out std_logic;
      ready_i   : in  std_logic
    );
  end component;

begin

  u_aes : aes256_core
    port map (
      clk_i     => clk_i,
      rst_ni    => rst_ni,
      key_i     => key_i,
      data_i    => data_i,
      encrypt_i => encrypt_i,
      valid_i   => valid_i,
      ready_o   => ready_o,
      data_o    => data_o,
      valid_o   => valid_o,
      ready_i   => ready_i
    );

end architecture rtl;
