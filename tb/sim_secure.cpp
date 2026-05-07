// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (C) 2026 Ayoub Achour
//
// Verilator C++ harness for aes256_core_secure.
//
// Tests:
//   S1. NIST AES-256 vectors produce correct ciphertext/plaintext (regardless
//       of mask). 3 enc + 3 dec.
//   S2. Same key + same plaintext + DIFFERENT random_i -> same output
//       (mask invariance). 4 random masks.
//   S3. Mid-operation, the registered state_masked_q is NOT identical across
//       two runs with different random_i (sanity check that masking is
//       actually applied to the registered state).
//   S4. Force the round counter to disagree mid-op (via Verilator public
//       access) and verify fault_o asserts and ready_o de-asserts. Then reset
//       clears it and the core encrypts correctly post-reset.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>

#include "verilated.h"
#include "Vaes256_secure_tb.h"
#include "Vaes256_secure_tb___024root.h"

struct U128 { uint32_t w[4]; };
struct U256 { uint32_t w[8]; };

static U128 from_hex128(const char* hex) {
    U128 out{};
    if (std::strlen(hex) != 32) { std::fprintf(stderr, "bad hex128\n"); std::exit(2); }
    for (int byte = 0; byte < 16; byte++) {
        unsigned v;
        std::sscanf(hex + 2 * byte, "%2x", &v);
        int bit_hi = 127 - 8 * byte;
        int word   = bit_hi / 32;
        int shift  = bit_hi - word * 32 - 7;
        out.w[word] |= (uint32_t)(v & 0xff) << shift;
    }
    return out;
}

static U256 from_hex256(const char* hex) {
    U256 out{};
    if (std::strlen(hex) != 64) { std::fprintf(stderr, "bad hex256\n"); std::exit(2); }
    for (int byte = 0; byte < 32; byte++) {
        unsigned v;
        std::sscanf(hex + 2 * byte, "%2x", &v);
        int bit_hi = 255 - 8 * byte;
        int word   = bit_hi / 32;
        int shift  = bit_hi - word * 32 - 7;
        out.w[word] |= (uint32_t)(v & 0xff) << shift;
    }
    return out;
}

static std::string to_hex128(const U128& v) {
    char buf[33];
    for (int byte = 0; byte < 16; byte++) {
        int bit_hi = 127 - 8 * byte;
        int word   = bit_hi / 32;
        int shift  = bit_hi - word * 32 - 7;
        unsigned b = (v.w[word] >> shift) & 0xff;
        std::snprintf(buf + 2 * byte, 3, "%02x", b);
    }
    buf[32] = 0;
    return std::string(buf);
}

static bool eq128(const U128& a, const U128& b) {
    return a.w[0] == b.w[0] && a.w[1] == b.w[1] && a.w[2] == b.w[2] && a.w[3] == b.w[3];
}

static U128 read_data_o(const Vaes256_secure_tb* dut) {
    U128 v{};
    v.w[0] = dut->data_o[0]; v.w[1] = dut->data_o[1];
    v.w[2] = dut->data_o[2]; v.w[3] = dut->data_o[3];
    return v;
}

static void write_data_port(uint32_t* port, const U128& v) {
    port[0] = v.w[0]; port[1] = v.w[1]; port[2] = v.w[2]; port[3] = v.w[3];
}

static void write_key_port(uint32_t* port, const U256& v) {
    for (int i = 0; i < 8; i++) port[i] = v.w[i];
}

static vluint64_t g_time = 0;
static int g_failures = 0;

static void tick(Vaes256_secure_tb* dut) {
    dut->clk_i = 0; dut->eval(); g_time++;
    dut->clk_i = 1; dut->eval(); g_time++;
}

static void reset(Vaes256_secure_tb* dut) {
    dut->rst_ni = 0;
    dut->valid_i = 0; dut->ready_i = 0; dut->encrypt_i = 0;
    write_key_port(dut->key_i, U256{});
    write_data_port(dut->data_i, U128{});
    write_data_port(dut->random_i, U128{});
    for (int i = 0; i < 4; i++) tick(dut);
    dut->rst_ni = 1; tick(dut);
}

static U128 run_block(Vaes256_secure_tb* dut, const U256& key,
                      const U128& data, bool encrypt, const U128& rnd,
                      const char* label, int max_cycles = 64) {
    int waited = 0;
    while (!dut->ready_o) {
        tick(dut);
        if (++waited > max_cycles) {
            std::fprintf(stderr, "[%s] timeout ready_o\n", label);
            g_failures++; return U128{};
        }
    }
    write_key_port(dut->key_i, key);
    write_data_port(dut->data_i, data);
    write_data_port(dut->random_i, rnd);
    dut->encrypt_i = encrypt ? 1 : 0;
    dut->valid_i = 1;
    tick(dut);
    dut->valid_i = 0;
    write_key_port(dut->key_i, U256{});
    write_data_port(dut->data_i, U128{});
    write_data_port(dut->random_i, U128{});

    waited = 0;
    while (!dut->valid_o) {
        tick(dut);
        if (++waited > max_cycles) {
            std::fprintf(stderr, "[%s] timeout valid_o\n", label);
            g_failures++; return U128{};
        }
    }
    U128 result = read_data_o(dut);
    dut->ready_i = 1; tick(dut); dut->ready_i = 0;
    return result;
}

struct Vec {
    const char* name; const char* key; const char* pt; const char* ct;
};
// FIPS-197 App.C.3 + 2 NIST SP 800-38A F.1.5 vectors.
static const Vec kVectors[] = {
    {"FIPS-197 App.C.3",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089"},
    {"NIST SP 800-38A F.1.5 #1",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "6bc1bee22e409f96e93d7e117393172a",
        "f3eed1bdb5d2a03c064b5a7e3db181f8"},
    {"NIST SP 800-38A F.1.5 #2",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "591ccb10d410ed26dc5ba74a31362870"},
};
static constexpr int kNumVectors = sizeof(kVectors) / sizeof(kVectors[0]);

// ---------------------------------------------------------------------------
static void test_correctness(Vaes256_secure_tb* dut) {
    std::printf("---- Test S1: NIST AES-256 vectors with secure core ----\n");
    U128 rnd = from_hex128("a1b2c3d4e5f60718293a4b5c6d7e8f90");
    for (int i = 0; i < kNumVectors; i++) {
        const Vec& v = kVectors[i];
        U256 key = from_hex256(v.key);
        U128 pt  = from_hex128(v.pt);
        U128 ct_exp = from_hex128(v.ct);
        U128 ct = run_block(dut, key, pt, true, rnd, v.name);
        if (eq128(ct, ct_exp)) std::printf("  +PASS enc %s\n", v.name);
        else { std::printf("  +FAIL enc %s exp=%s got=%s\n", v.name,
               to_hex128(ct_exp).c_str(), to_hex128(ct).c_str()); g_failures++; }
        U128 pt2 = run_block(dut, key, ct, false, rnd, v.name);
        if (eq128(pt2, pt)) std::printf("  +PASS dec %s\n", v.name);
        else { std::printf("  +FAIL dec %s exp=%s got=%s\n", v.name,
               to_hex128(pt).c_str(), to_hex128(pt2).c_str()); g_failures++; }
    }
}

static void test_mask_invariance(Vaes256_secure_tb* dut) {
    std::printf("---- Test S2: output invariant under random_i variation ----\n");
    U256 key = from_hex256(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    U128 pt  = from_hex128("6bc1bee22e409f96e93d7e117393172a");
    U128 ct_exp = from_hex128("f3eed1bdb5d2a03c064b5a7e3db181f8");
    const char* rnds[] = {
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "0123456789abcdeffedcba9876543210",
        "deadbeefcafebabe1337c0debaadf00d",
    };
    int fail = 0;
    for (auto r : rnds) {
        U128 rnd = from_hex128(r);
        U128 ct = run_block(dut, key, pt, true, rnd, "mask-inv");
        if (!eq128(ct, ct_exp)) {
            std::printf("  +FAIL random_i=%s -> ct=%s\n", r, to_hex128(ct).c_str());
            fail++;
        }
    }
    if (fail == 0) std::printf("  +PASS mask_invariance 4/4 random masks produce identical ct\n");
    else { std::printf("  +FAIL mask_invariance %d/4\n", fail); g_failures++; }
}

static void test_internal_state_differs(Vaes256_secure_tb* dut) {
    std::printf("---- Test S3: registered state differs between mask values ----\n");
    // Reach into the DUT and snapshot state_masked_q after the same number of
    // cycles on two runs with different random_i. They must differ.
    U256 key = from_hex256(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    U128 pt  = from_hex128("6bc1bee22e409f96e93d7e117393172a");

    auto sample_state_at_run_cycle = [&](const char* rnd_hex) -> U128 {
        while (!dut->ready_o) tick(dut);
        U128 rnd = from_hex128(rnd_hex);
        write_key_port(dut->key_i, key);
        write_data_port(dut->data_i, pt);
        write_data_port(dut->random_i, rnd);
        dut->encrypt_i = 1; dut->valid_i = 1;
        tick(dut);
        dut->valid_i = 0;
        write_key_port(dut->key_i, U256{});
        write_data_port(dut->data_i, U128{});
        write_data_port(dut->random_i, U128{});
        // Run 12 cycles to be in S_RUN (after the 7-cycle expand, ~5 rounds in).
        for (int i = 0; i < 12; i++) tick(dut);
        U128 s{};
        auto* root = dut->rootp;
        s.w[0] = root->aes256_secure_tb__DOT__u_dut__DOT__state_masked_q[0];
        s.w[1] = root->aes256_secure_tb__DOT__u_dut__DOT__state_masked_q[1];
        s.w[2] = root->aes256_secure_tb__DOT__u_dut__DOT__state_masked_q[2];
        s.w[3] = root->aes256_secure_tb__DOT__u_dut__DOT__state_masked_q[3];
        // Drain and reset for next call
        while (!dut->valid_o) tick(dut);
        dut->ready_i = 1; tick(dut); dut->ready_i = 0;
        return s;
    };

    U128 s_a = sample_state_at_run_cycle("00000000000000000000000000000000");
    U128 s_b = sample_state_at_run_cycle("ffffffffffffffffffffffffffffffff");
    if (!eq128(s_a, s_b)) {
        std::printf("  +PASS internal_state_differs (snapshot A=%s B=%s)\n",
                    to_hex128(s_a).c_str(), to_hex128(s_b).c_str());
    } else {
        std::printf("  +FAIL internal_state_differs (both runs registered identical state %s)\n",
                    to_hex128(s_a).c_str());
        g_failures++;
    }
}

static void test_fault_detection(Vaes256_secure_tb* dut) {
    std::printf("---- Test S4: round counter fault injection -> fault_o ----\n");
    reset(dut);
    while (!dut->ready_o) tick(dut);
    U256 key = from_hex256(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    U128 pt  = from_hex128("6bc1bee22e409f96e93d7e117393172a");
    U128 rnd = from_hex128("a1b2c3d4e5f60718293a4b5c6d7e8f90");
    write_key_port(dut->key_i, key);
    write_data_port(dut->data_i, pt);
    write_data_port(dut->random_i, rnd);
    dut->encrypt_i = 1; dut->valid_i = 1;
    tick(dut);
    dut->valid_i = 0;
    write_key_port(dut->key_i, U256{});
    write_data_port(dut->data_i, U128{});
    write_data_port(dut->random_i, U128{});

    // Run a few cycles to be in S_EXPAND or S_RUN.
    for (int i = 0; i < 12; i++) tick(dut);

    // Inject fault: corrupt round_q2 via flat-public access.
    auto* root = dut->rootp;
    root->aes256_secure_tb__DOT__u_dut__DOT__round_q2 = 0xF;  // garbage
    tick(dut);

    if (!dut->fault_o) {
        std::printf("  +FAIL fault_o not asserted after counter corruption\n");
        g_failures++;
        return;
    }
    if (dut->ready_o) {
        std::printf("  +FAIL ready_o still high under fault (should be low)\n");
        g_failures++;
        return;
    }
    // Reset must clear fault.
    dut->rst_ni = 0;
    for (int i = 0; i < 4; i++) tick(dut);
    dut->rst_ni = 1; tick(dut);
    if (dut->fault_o) {
        std::printf("  +FAIL fault_o sticky after reset\n");
        g_failures++;
        return;
    }
    if (!dut->ready_o) {
        std::printf("  +FAIL ready_o low after reset (FSM did not recover)\n");
        g_failures++;
        return;
    }
    // And the core encrypts correctly post-reset.
    U128 ct_exp = from_hex128("f3eed1bdb5d2a03c064b5a7e3db181f8");
    U128 ct = run_block(dut, key, pt, true, rnd, "post-fault");
    if (!eq128(ct, ct_exp)) {
        std::printf("  +FAIL post-fault encrypt got=%s\n", to_hex128(ct).c_str());
        g_failures++;
        return;
    }
    std::printf("  +PASS fault_detection (counter corruption -> fault_o, reset clears, recovery OK)\n");
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* dut = new Vaes256_secure_tb();
    reset(dut);
    test_correctness(dut);
    test_mask_invariance(dut);
    test_internal_state_differs(dut);
    test_fault_detection(dut);
    dut->final();
    delete dut;
    if (g_failures == 0) { std::printf("\n+PASS all secure tests passed\n"); return 0; }
    std::printf("\n+FAIL %d failure(s)\n", g_failures); return 1;
}
