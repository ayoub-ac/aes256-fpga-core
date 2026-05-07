# Security model

This document describes what `aes256_core_secure` is designed to defend against,
what it is NOT designed to defend against, and how to evaluate the claims.

If you need a side-channel-resistant AES-256 core for a real product, read this
whole document and decide whether the threat model matches your deployment.
Don't trust marketing copy; trust the threat model and your own evaluation.

## What's in the secure variant

`rtl/aes256_core_secure.sv` is the hardened sibling of `aes256_core`. Same
algorithm (AES-256, FIPS-197), same I/O contract, plus a `random_i` input and
a `fault_o` output. The countermeasures it implements are:

### 1. State-level Boolean masking (1st-order)

The 128-bit cipher state register stores `state_xor_mask` and the mask
separately. The mask is sampled from `random_i` at the start of each block
(128 bits per block, matching the state width — not the 256-bit key width)
and is wiped at completion. The unmasked output is only revealed on the final
round.

**Random width choice**: the masked register is 128 bits wide because the
cipher state is 128 bits wide regardless of key size. The 256-bit cipher key
does not enter the masked state register; it is loaded directly into
`rk_q[0..1]` of the schedule. A 256-bit `random_i` would cost an extra
128 bits of TRNG entropy per block with no additional protection.

**What this protects:** simple power-analysis attacks that target the cipher
state register's transition activity. Two encryptions of the same plaintext
under the same key will toggle the state register through different bit
patterns depending on `random_i`, breaking the simple correlation model.

**What this does NOT protect:** the S-box LUT transitions themselves are still
computed on unmasked data inside the combinational round logic. A power
attacker measuring leakage at the S-box (rather than at the state register)
can still recover the key via 1st-order DPA. To close this gap requires a
masked S-box (e.g. RSM, Canright-masked, or a threshold implementation), which
is a future variant.

The reference scheme is Boolean masking as described in:
- E. Trichina, "Combinational Logic Design for AES SubByte Transformation on
  Masked Data," IACR ePrint 2003/236.
- We implement only the state-register-level part of that scheme; we do not
  yet implement the masked combinational SubBytes that the full scheme
  requires for 1st-order DPA resistance on the S-box.

### 2. Duplicated round counter with fault detector

The round counter is duplicated as `round_q` and `round_q2`. Every clock the
two are compared; a mismatch transitions the FSM into `S_FAULT` and asserts
`fault_o`. The output is wiped and `ready_o` is held low until the next reset.

**What this protects:** single-bit fault injection on either of the two round
counter flip-flops (laser fault injection, EMFI, voltage glitching that
flips an FF). An attacker who can flip exactly one bit in `round_q` to skip a
round (a classic AES fault attack) is detected.

**What this does NOT protect:** simultaneous identical fault injection on
both counters. Faults on the cipher state register itself (still possible to
mount differential fault attacks on AES rounds). For full DFA resistance the
state register would also need to be duplicated and compared.

### 3. Constant-time FSM

There are no data-dependent branches in the FSM. Every block takes the same
23 cycles regardless of key or plaintext content (7 expand + 14 round + 2
handshake), and there are no early-exit or fast-path branches. This is
verified by inspection of the FSM and by the back-to-back test in the basic
testbench, which observes a constant 23 cycles/block across many distinct
inputs.

**What this protects:** timing attacks that observe block-completion latency.

### 4. Constant-cycle output reveal + state wipe

The unmasked ciphertext/plaintext is revealed only in `S_DONE`, on the cycle
after the final round. The output and registered masked state are wiped on
transition back to `S_IDLE`. The mask itself is wiped one cycle earlier
(end of the final round). There is no scenario where an attacker can read
partial state via `data_o`.

## What's NOT covered (be honest)

This list is deliberately exhaustive so that purchasers can evaluate fit:

- **Higher-order DPA**: 2nd-order and above attacks combine multiple leakage
  points and are not addressed by 1st-order Boolean masking. Mitigation
  requires higher-order masking schemes; not implemented.
- **EM (electromagnetic) analysis** and **template attacks**: not specifically
  countered. Power balancing in this design is limited to keeping the FSM
  active during all cycles; differential routing and constant-Hamming-weight
  encodings are out of scope.
- **Cache / micro-architectural side channels**: not applicable (this is RTL,
  not software), but if you place this core into a system with a shared bus
  or shared memory, those channels can leak.
- **S-box DPA**: as noted above, the S-box LUT is unmasked in the
  combinational round logic. Attackers measuring at the S-box transition can
  recover the key with standard CPA / DPA techniques.
- **Multi-bit fault injection** on the round counter (faults that flip both
  copies identically): not detected.
- **Fault injection on the state register**: not duplicated, not protected.
- **Power glitch attacks** on the FF setup/hold window are out of scope.
- **Invasive attacks** (decap, microprobing) are entirely out of scope.

If your deployment threat model includes any of the above and the rest of
your system relies on AES integrity, this core is not enough on its own.

## Compliance claims

- **FIPS-197 conformance**: yes. The RTL implements the AES-256 block cipher
  exactly as specified in FIPS-197 and is verified against published NIST
  test vectors (FIPS-197 Appendix C.3, NIST SP 800-38A F.1.5 / F.1.6).
- **FIPS-140-2 / FIPS-140-3 certification**: NOT claimed. FIPS-140 is a
  module-level certification covering far more than the algorithm
  (RNG quality, key zeroization, role-based authentication, physical
  security, etc.) and is the responsibility of the integrator. This core
  implements one of the building blocks; it is not by itself a FIPS-140
  cryptographic module.
- **Common Criteria**: not evaluated.
- **NIST CAVP test certificate**: the RTL passes NIST FIPS-197 known-answer
  tests in simulation, but is not registered with NIST CAVP. CAVP requires a
  test harness running on the certified platform, which is the integrator's
  responsibility.

## Test methodology used to validate the security claims

The Verilator testbench in `tb/sim_secure.cpp` runs:

1. **Functional correctness on NIST test vectors** with a non-zero `random_i`.
   Verifies that masking does not change the produced ciphertext. 3 enc + 3
   dec across FIPS-197 App.C.3 and SP 800-38A F.1.5 vectors. ([+PASS] in
   `test_secure.log`, suite `S1`.)
2. **Mask invariance**: same key + same plaintext, four different `random_i`
   values, same ciphertext expected. ([+PASS], suite `S2`.)
3. **Internal state differs**: snapshot the registered `state_masked_q` mid-
   operation under two distinct `random_i` values; the registered state must
   differ. This is a direct test that masking is actually applied to the
   register, not optimized away. ([+PASS], suite `S3`.)
4. **Fault injection**: corrupt `round_q2` mid-operation through Verilator's
   public-flat-rw access, verify `fault_o` rises and `ready_o` falls. Then
   reset, verify `fault_o` clears and the core encrypts correctly post-reset.
   ([+PASS], suite `S4`.)

We do NOT run experimental DPA / CPA against the bitstream. The 1st-order DPA
resistance claim on the state register is **design intent**, derived from the
masking scheme. If you need an experimentally-verified claim, that is a
separate engagement that requires a real FPGA, an oscilloscope, and a
trace-collection campaign measured in days or weeks. We do not sell that as
part of the Premium tier.

In other words: the secure variant is "designed to resist 1st-order DPA on
the cipher state register per the published Boolean masking scheme" — not
"DPA-certified."

## How to use the secure core safely

1. Drive `random_i` from a true random number generator (not a PRNG seeded
   from the same key). Use a fresh 128 bits per block. If your platform has
   a hardware TRNG, use it; if not, do not deploy the secure variant.
2. Hold `rst_ni` low for ≥4 cycles after power-on and before the first block.
3. Watch `fault_o`. If it ever rises, treat it as a security event: the most
   likely cause is fault injection. Reset and consider whether to re-encrypt.
4. The secure variant is not a substitute for protocol-level measures like
   nonce uniqueness in CTR mode or AEAD authentication tags. Use it inside
   an AEAD construction (GCM, CCM, ChaCha20-Poly1305-style alternatives) for
   real systems.

## Reporting issues

Found a bug, a side channel we missed, or a discrepancy with FIPS-197?
Open an issue or contact the email in the README. Coordinated disclosure
welcome. We do not currently offer a bug bounty.
