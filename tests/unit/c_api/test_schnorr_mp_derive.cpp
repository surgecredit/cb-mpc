#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include <cbmpc/c_api/job.h>
#include <cbmpc/c_api/schnorr_mp.h>
#include <cbmpc/core/error.h>
#include <cbmpc/internal/crypto/base_ecc_secp256k1.h>

#include "test_transport_harness.h"

namespace {

using coinbase::testutils::mpc_net_context_t;
using coinbase::testutils::capi_harness::make_transport;
using coinbase::testutils::capi_harness::run_mp;
using coinbase::testutils::capi_harness::transport_ctx_t;

static void expect_eq(cmem_t a, cmem_t b) {
  ASSERT_EQ(a.size, b.size);
  if (a.size > 0) ASSERT_EQ(std::memcmp(a.data, b.data, static_cast<size_t>(a.size)), 0);
}

}  // namespace

TEST(CApiSchnorrMpDerive, DeriveThenSign4p) {
  constexpr int n = 4;
  std::vector<std::shared_ptr<mpc_net_context_t>> peers;
  for (int i = 0; i < n; i++) peers.push_back(std::make_shared<mpc_net_context_t>(i));
  for (const auto& p : peers) p->init_with_peers(peers);
  std::atomic<int> free_calls[n];
  transport_ctx_t ctx[n];
  cbmpc_transport_t transports[n];
  for (int i = 0; i < n; i++) {
    free_calls[i].store(0);
    ctx[i] = transport_ctx_t{peers[static_cast<size_t>(i)], &free_calls[i]};
    transports[i] = make_transport(&ctx[i]);
  }
  const char* party_names[n] = {"p0", "p1", "p2", "p3"};

  std::vector<cmem_t> key_blobs(n, cmem_t{nullptr, 0});
  std::vector<cmem_t> sids(n, cmem_t{nullptr, 0});
  std::vector<cbmpc_error_t> rvs;
  run_mp(
      peers,
      [&](int i) {
        const cbmpc_mp_job_t job = {i, party_names, n, &transports[i]};
        return cbmpc_schnorr_mp_dkg_additive(&job, CBMPC_CURVE_SECP256K1, &key_blobs[static_cast<size_t>(i)],
                                             &sids[static_cast<size_t>(i)]);
      },
      rvs);
  for (auto rv : rvs) ASSERT_EQ(rv, CBMPC_SUCCESS);

  uint8_t chain_code_bytes[32];
  for (int i = 0; i < 32; i++) chain_code_bytes[i] = static_cast<uint8_t>(0xa0 + i);
  const cmem_t chain_code = {chain_code_bytes, 32};
  const uint32_t path[2] = {2, 0};

  std::vector<cmem_t> derived(n, cmem_t{nullptr, 0});
  for (int i = 0; i < n; i++) {
    ASSERT_EQ(cbmpc_schnorr_mp_derive_non_hardened(key_blobs[static_cast<size_t>(i)], chain_code, path, 2,
                                                   &derived[static_cast<size_t>(i)]),
              CBMPC_SUCCESS);
    ASSERT_GT(derived[static_cast<size_t>(i)].size, 0);
  }

  cmem_t parent_pub = {nullptr, 0};
  ASSERT_EQ(cbmpc_schnorr_mp_get_public_key_compressed(key_blobs[0], &parent_pub), CBMPC_SUCCESS);
  cmem_t pub0 = {nullptr, 0};
  ASSERT_EQ(cbmpc_schnorr_mp_get_public_key_compressed(derived[0], &pub0), CBMPC_SUCCESS);
  ASSERT_EQ(pub0.size, 33);
  ASSERT_NE(std::memcmp(pub0.data, parent_pub.data, 33), 0);
  for (int i = 1; i < n; i++) {
    cmem_t pub_i = {nullptr, 0};
    ASSERT_EQ(cbmpc_schnorr_mp_get_public_key_compressed(derived[static_cast<size_t>(i)], &pub_i), CBMPC_SUCCESS);
    expect_eq(pub_i, pub0);
    cbmpc_cmem_free(pub_i);
  }
  cbmpc_cmem_free(parent_pub);

  coinbase::crypto::ecc_point_t Q;
  ASSERT_EQ(Q.from_bin(coinbase::crypto::curve_secp256k1, coinbase::mem_t(pub0.data, pub0.size)), SUCCESS);
  cbmpc_cmem_free(pub0);

  uint8_t msg_bytes[32];
  for (int i = 0; i < 32; i++) msg_bytes[i] = static_cast<uint8_t>(i);
  const cmem_t msg = {msg_bytes, 32};
  std::vector<cmem_t> sigs(n, cmem_t{nullptr, 0});
  run_mp(
      peers,
      [&](int i) {
        const cbmpc_mp_job_t job = {i, party_names, n, &transports[i]};
        return cbmpc_schnorr_mp_sign_additive(&job, derived[static_cast<size_t>(i)], msg, /*sig_receiver=*/1,
                                              &sigs[static_cast<size_t>(i)]);
      },
      rvs);
  for (auto rv : rvs) ASSERT_EQ(rv, CBMPC_SUCCESS);
  ASSERT_EQ(sigs[1].size, 64);
  ASSERT_EQ(coinbase::crypto::bip340::verify(Q, coinbase::mem_t(msg_bytes, 32), coinbase::mem_t(sigs[1].data, 64)),
            SUCCESS);

  for (int i = 0; i < n; i++) {
    cbmpc_cmem_free(key_blobs[static_cast<size_t>(i)]);
    cbmpc_cmem_free(sids[static_cast<size_t>(i)]);
    cbmpc_cmem_free(derived[static_cast<size_t>(i)]);
    cbmpc_cmem_free(sigs[static_cast<size_t>(i)]);
  }
}

TEST(CApiSchnorrMpDerive, RejectsBadArgs) {
  uint8_t cc[32] = {0};
  const uint32_t path[1] = {0};
  const uint32_t hardened[1] = {0x80000000u};
  cmem_t out = {nullptr, 0};
  uint8_t junk[8] = {1, 2, 3, 4, 5, 6, 7, 8};

  ASSERT_NE(cbmpc_schnorr_mp_derive_non_hardened(cmem_t{junk, 8}, cmem_t{cc, 32}, path, 1, &out), CBMPC_SUCCESS);
  ASSERT_EQ(out.data, nullptr);
  ASSERT_NE(cbmpc_schnorr_mp_derive_non_hardened(cmem_t{junk, 8}, cmem_t{cc, 32}, hardened, 1, &out), CBMPC_SUCCESS);
  ASSERT_NE(cbmpc_schnorr_mp_derive_non_hardened(cmem_t{junk, 8}, cmem_t{cc, 31}, path, 1, &out), CBMPC_SUCCESS);
  ASSERT_NE(cbmpc_schnorr_mp_derive_non_hardened(cmem_t{junk, 8}, cmem_t{cc, 32}, path, 0, &out), CBMPC_SUCCESS);
  ASSERT_NE(cbmpc_schnorr_mp_derive_non_hardened(cmem_t{junk, 8}, cmem_t{cc, 32}, nullptr, 1, &out), CBMPC_SUCCESS);
  ASSERT_EQ(cbmpc_schnorr_mp_derive_non_hardened(cmem_t{junk, 8}, cmem_t{cc, 32}, path, 1, nullptr), E_BADARG);
}
