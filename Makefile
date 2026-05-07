# AES-256 FPGA core - build / lint / sim / synth
#
# Targets:
#   make lint         verilator --lint-only on basic + secure + pipelined RTL
#   make sim          build the basic Verilator simulator
#   make test         build + run basic sim, check for "+PASS"
#   make sim-secure   build the secure-variant simulator
#   make test-secure  build + run secure sim, check for "+PASS"
#   make test-all     run both suites
#   make synth        Yosys: ice40 + ecp5 + xilinx generic for the basic core
#   make synth-pipelined / synth-secure   same for the variants
#   make synth_report run all available toolchains and emit SYNTH_REPORT.md
#   make vhdl-test    GHDL+Verilator co-sim of the VHDL wrapper (if installed)
#   make clean        remove build artifacts

VERILATOR ?= verilator
YOSYS     ?= yosys
GHDL      ?= ghdl
VIVADO    ?= vivado
QUARTUS   ?= quartus_sh

RTL_BASIC := \
    rtl/aes_sbox.sv \
    rtl/aes_inv_sbox.sv \
    rtl/aes_key_expand_256.sv \
    rtl/aes_round.sv \
    rtl/aes256_core.sv

RTL_SECURE := \
    rtl/aes_sbox.sv \
    rtl/aes_inv_sbox.sv \
    rtl/aes_key_expand_256.sv \
    rtl/aes_round.sv \
    rtl/aes256_core_secure.sv

RTL_PIPELINED := \
    rtl/aes_sbox.sv \
    rtl/aes_inv_sbox.sv \
    rtl/aes_key_expand_256.sv \
    rtl/aes_round.sv \
    rtl/aes256_core_pipelined.sv

TB_TOP        := tb/aes256_core_tb.sv
TB_TOP_AUX    := tb/aes256_core_assertions.sv tb/aes256_core_cov.sv
TB_CPP        := tb/sim_main.cpp
TB_SECURE_TOP := tb/aes256_secure_tb.sv
TB_SECURE_CPP := tb/sim_secure.cpp

VFLAGS := -Wall -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-HIERBLOCK

.PHONY: lint sim test sim-secure test-secure test-all \
        synth synth-pipelined synth-secure synth_report \
        vhdl-test clean regen_vectors

lint:
	$(VERILATOR) --lint-only $(VFLAGS) --top-module aes256_core_tb \
	    $(RTL_BASIC) $(TB_TOP) $(TB_TOP_AUX)
	$(VERILATOR) --lint-only $(VFLAGS) --top-module aes256_secure_tb \
	    $(RTL_SECURE) $(TB_SECURE_TOP)
	$(VERILATOR) --lint-only $(VFLAGS) --top-module aes256_core_pipelined \
	    $(RTL_PIPELINED)

sim: obj_dir/Vaes256_core_tb

obj_dir/Vaes256_core_tb: $(RTL_BASIC) $(TB_TOP) $(TB_TOP_AUX) $(TB_CPP)
	$(VERILATOR) --cc --exe --build $(VFLAGS) --assert --public-flat-rw \
	    --top-module aes256_core_tb \
	    $(RTL_BASIC) $(TB_TOP) $(TB_TOP_AUX) $(TB_CPP) \
	    -o Vaes256_core_tb

test: sim
	./obj_dir/Vaes256_core_tb | tee test.log
	@grep -q "+PASS" test.log && echo "TESTS PASSED" || (echo "TESTS FAILED" && exit 1)

sim-secure: obj_dir_secure/Vaes256_secure_tb

obj_dir_secure/Vaes256_secure_tb: $(RTL_SECURE) $(TB_SECURE_TOP) $(TB_SECURE_CPP)
	$(VERILATOR) --cc --exe --build $(VFLAGS) \
	    --public-flat-rw \
	    --Mdir obj_dir_secure \
	    --top-module aes256_secure_tb \
	    $(RTL_SECURE) $(TB_SECURE_TOP) $(TB_SECURE_CPP) \
	    -o Vaes256_secure_tb

test-secure: sim-secure
	./obj_dir_secure/Vaes256_secure_tb | tee test_secure.log
	@grep -q "+PASS all secure" test_secure.log && echo "SECURE TESTS PASSED" || (echo "SECURE TESTS FAILED" && exit 1)

test-all: test test-secure

# ---------- Open synthesis (Yosys) ------------------------------------------
synth:
	$(YOSYS) -p "read_verilog -sv $(RTL_BASIC); hierarchy -top aes256_core; synth_ice40 -top aes256_core; stat" \
	    | tee synth_ice40.log
	$(YOSYS) -p "read_verilog -sv $(RTL_BASIC); hierarchy -top aes256_core; synth_ecp5 -top aes256_core -abc9; stat" \
	    | tee synth_ecp5.log
	$(YOSYS) -p "read_verilog -sv $(RTL_BASIC); hierarchy -top aes256_core; synth_xilinx -top aes256_core; stat" \
	    | tee synth_xilinx.log

synth-pipelined:
	$(YOSYS) -p "read_verilog -sv $(RTL_PIPELINED); hierarchy -top aes256_core_pipelined; synth_xilinx -top aes256_core_pipelined; stat" \
	    | tee synth_pipelined_xilinx.log

synth-secure:
	$(YOSYS) -p "read_verilog -sv $(RTL_SECURE); hierarchy -top aes256_core_secure; synth_xilinx -top aes256_core_secure; stat" \
	    | tee synth_secure_xilinx.log

# ---------- Cross-toolchain synthesis report --------------------------------
# Runs every available toolchain and writes SYNTH_REPORT.md. Missing tools are
# noted as "skipped"; existing tools produce real LUT/FF numbers.
synth_report:
	@bash scripts/synth_report.sh

# ---------- VHDL co-sim (optional) ------------------------------------------
vhdl-test:
	@which $(GHDL) >/dev/null 2>&1 || { echo "ghdl not installed - skipping vhdl-test"; exit 0; }
	@which $(VERILATOR) >/dev/null 2>&1 || { echo "verilator not installed"; exit 1; }
	@bash scripts/vhdl_cosim.sh

clean:
	rm -rf obj_dir obj_dir_secure test.log test_secure.log \
	    synth_ice40.log synth_ecp5.log synth_xilinx.log \
	    synth_pipelined_xilinx.log synth_secure_xilinx.log \
	    synth_report/ SYNTH_REPORT.md

regen_vectors:
	python tb/gen_random_vectors.py > tb/random_vectors.h
