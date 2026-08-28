#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <cbmpc/api/curve.h>
#include <cbmpc/api/schnorr_mp.h>
#include <cbmpc/core/bip32_path.h>
#include <cbmpc/internal/crypto/base.h>

#include "test_transport_harness.h"

namespace {

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::api::bip32_path_t;
using coinbase::api::curve_id;
using coinbase::api::job_mp_t;
using coinbase::api::party_idx_t;
using coinbase::testutils::mpc_net_context_t;
using coinbase::testutils::api_harness::local_api_transport_t;
using coinbase::testutils::api_harness::run_mp;

TEST(SchnorrMPDerive, DeriveThenSign) {
  constexpr int n = 4;
  std::vector<std::shared_ptr<mpc_net_context_t>> peers;
  for (int i = 0; i < n; i++) peers.push_back(std::make_shared<mpc_net_context_t>(i));
  for (const auto& p : peers) p->init_with_peers(peers);
  std::vector<std::shared_ptr<local_api_transport_t>> transports;
  for (const auto& p : peers) transports.push_back(std::make_shared<local_api_transport_t>(p));
  const std::vector<std::string> names = {"p0", "p1", "p2", "p3"};
  std::vector<std::string_view> name_views(names.begin(), names.end());

  std::vector<buf_t> keys(n), sids(n), sigs(n);
  std::vector<error_t> rvs;
  run_mp(
      peers,
      [&](int i) {
        job_mp_t job{static_cast<party_idx_t>(i), name_views, *transports[i]};
        return coinbase::api::schnorr_mp::dkg_additive(job, curve_id::secp256k1, keys[i], sids[i]);
      },
      rvs);
  for (auto rv : rvs) ASSERT_EQ(rv, SUCCESS);

  const buf_t chain_code = coinbase::crypto::gen_random(32);
  const std::vector<bip32_path_t> paths = {bip32_path_t{{0, 0}}, bip32_path_t{{2, 0}}};

  std::vector<std::vector<buf_t>> derived(n);
  for (int i = 0; i < n; i++) {
    ASSERT_EQ(coinbase::api::schnorr_mp::derive_non_hardened(keys[i], chain_code, paths, derived[i]), SUCCESS);
    ASSERT_EQ(derived[i].size(), paths.size());
  }

  buf_t parent_xonly;
  ASSERT_EQ(coinbase::api::schnorr_mp::extract_public_key_xonly(keys[0], parent_xonly), SUCCESS);

  for (size_t k = 0; k < paths.size(); k++) {
    buf_t xonly0;
    ASSERT_EQ(coinbase::api::schnorr_mp::extract_public_key_xonly(derived[0][k], xonly0), SUCCESS);
    EXPECT_EQ(xonly0.size(), 32);
    EXPECT_NE(xonly0, parent_xonly);
    for (int i = 1; i < n; i++) {
      buf_t xonly_i;
      ASSERT_EQ(coinbase::api::schnorr_mp::extract_public_key_xonly(derived[i][k], xonly_i), SUCCESS);
      EXPECT_EQ(xonly_i, xonly0);
    }

    buf_t msg = coinbase::crypto::gen_random(32);
    run_mp(
        peers,
        [&](int i) {
          job_mp_t job{static_cast<party_idx_t>(i), name_views, *transports[i]};
          return coinbase::api::schnorr_mp::sign_additive(job, derived[i][k], msg, 0, sigs[i]);
        },
        rvs);
    for (auto rv : rvs) ASSERT_EQ(rv, SUCCESS);
    EXPECT_EQ(sigs[0].size(), 64);
  }
}

TEST(SchnorrMPDerive, RejectsAcBlobAndHardened) {
  constexpr int n = 2;
  std::vector<std::shared_ptr<mpc_net_context_t>> peers;
  for (int i = 0; i < n; i++) peers.push_back(std::make_shared<mpc_net_context_t>(i));
  for (const auto& p : peers) p->init_with_peers(peers);
  std::vector<std::shared_ptr<local_api_transport_t>> transports;
  for (const auto& p : peers) transports.push_back(std::make_shared<local_api_transport_t>(p));
  const std::vector<std::string> names = {"p0", "p1"};
  std::vector<std::string_view> name_views(names.begin(), names.end());

  std::vector<buf_t> keys(n), sids(n);
  std::vector<error_t> rvs;
  run_mp(
      peers,
      [&](int i) {
        job_mp_t job{static_cast<party_idx_t>(i), name_views, *transports[i]};
        return coinbase::api::schnorr_mp::dkg_additive(job, curve_id::secp256k1, keys[i], sids[i]);
      },
      rvs);
  for (auto rv : rvs) ASSERT_EQ(rv, SUCCESS);

  std::vector<buf_t> out;
  const buf_t chain_code = coinbase::crypto::gen_random(32);
  EXPECT_NE(coinbase::api::schnorr_mp::derive_non_hardened(keys[0], chain_code, {bip32_path_t{{0x80000000u}}}, out),
            SUCCESS);
  EXPECT_NE(coinbase::api::schnorr_mp::derive_non_hardened(keys[0], coinbase::crypto::gen_random(16),
                                                           {bip32_path_t{{0}}}, out),
            SUCCESS);
  EXPECT_NE(coinbase::api::schnorr_mp::derive_non_hardened(buf_t(8), chain_code, {bip32_path_t{{0}}}, out), SUCCESS);

  // Bounds are enforced at this layer too, before the blob is parsed.
  {
    std::vector<bip32_path_t> too_many;
    for (uint32_t i = 0; i < 257; i++) too_many.push_back(bip32_path_t{{i}});
    EXPECT_NE(coinbase::api::schnorr_mp::derive_non_hardened(keys[0], chain_code, too_many, out), SUCCESS);
    bip32_path_t too_deep;
    too_deep.indices.assign(256, 0);
    EXPECT_NE(coinbase::api::schnorr_mp::derive_non_hardened(keys[0], chain_code, {too_deep}, out), SUCCESS);
    EXPECT_NE(coinbase::api::schnorr_mp::derive_non_hardened(keys[0], chain_code, {}, out), SUCCESS);
  }
}

}  // namespace
