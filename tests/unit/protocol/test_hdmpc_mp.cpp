#include <gtest/gtest.h>

#include <cbmpc/internal/core/log.h>
#include <cbmpc/internal/protocol/hd_keyset_mp.h>
#include <cbmpc/internal/protocol/schnorr_mp.h>

#include "utils/local_network/mpc_tester.h"

namespace {

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::testutils;

class HDMPC_MP : public Network4PC {
 protected:
  static void check_keys(const std::vector<eckey::key_share_mp_t>& keys) {
    crypto::vartime_scope_t vartime_scope;
    const auto& G = keys[0].curve.generator();
    ecc_point_t Q_from_x = keys[0].x_share * G;
    for (size_t i = 1; i < keys.size(); i++) {
      EXPECT_EQ(keys[i].Q, keys[0].Q);
      EXPECT_EQ(keys[i].Qis, keys[0].Qis);
      Q_from_x += keys[i].x_share * G;
    }
    EXPECT_EQ(keys[0].Q, Q_from_x);
    EXPECT_EQ(SUM(keys[0].Qis), keys[0].Q);
    for (const auto& key : keys) EXPECT_EQ(key.x_share * G, key.Qis.at(key.party_name));
  }

  static bip32_path_t path(std::initializer_list<uint32_t> indices) {
    bip32_path_t p;
    for (uint32_t i : indices) p.append(i);
    return p;
  }
};

TEST_F(HDMPC_MP, DeriveAndSign) {
  constexpr int n = 4;
  std::vector<eckey::key_share_mp_t> keys(n);
  std::vector<std::vector<eckey::key_share_mp_t>> derived(n);
  const buf_t chain_code = crypto::gen_random(32);
  const std::vector<bip32_path_t> paths = {path({0, 0}), path({2, 0})};
  const buf_t data = crypto::gen_random(32);

  mpc_runner->run_mpc([&](job_mp_t& job) {
    error_t rv = UNINITIALIZED_ERROR;
    int i = job.get_party_idx();
    buf_t sid;
    rv = eckey::key_share_mp_t::dkg(job, crypto::curve_secp256k1, keys[i], sid);
    ASSERT_EQ(rv, 0);

    rv = normal_derive_mp(keys[i], chain_code, paths, derived[i]);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(derived[i].size(), paths.size());

    for (size_t k = 0; k < paths.size(); k++) {
      buf_t sig;
      rv = schnorrmp::sign(job, derived[i][k], data, party_idx_t(0), sig, schnorrmp::variant_e::BIP340);
      ASSERT_EQ(rv, 0);
    }
  });

  check_keys(keys);
  for (size_t k = 0; k < paths.size(); k++) {
    std::vector<eckey::key_share_mp_t> at_k;
    for (int i = 0; i < n; i++) at_k.push_back(derived[i][k]);
    check_keys(at_k);
    EXPECT_NE(at_k[0].Q, keys[0].Q);
  }

  // Q̃ matches an independent BIP-32 derivation from the public values alone.
  crypto::vartime_scope_t vartime_scope;
  const auto& G = keys[0].curve.generator();
  std::vector<bn_t> delta = non_hard_derive(keys[0].Q, chain_code, paths);
  for (size_t k = 0; k < paths.size(); k++) EXPECT_EQ(derived[0][k].Q, keys[0].Q + delta[k] * G);

  // Only the first party by name moved its x_share.
  const crypto::pname_t& first = keys[0].Qis.begin()->first;
  for (int i = 0; i < n; i++) {
    bool moved = derived[i][0].x_share != keys[i].x_share;
    EXPECT_EQ(moved, keys[i].party_name == first);
  }
}

TEST_F(HDMPC_MP, RejectsBadInput) {
  constexpr int n = 4;
  std::vector<eckey::key_share_mp_t> keys(n);
  mpc_runner->run_mpc([&](job_mp_t& job) {
    buf_t sid;
    ASSERT_EQ(eckey::key_share_mp_t::dkg(job, crypto::curve_secp256k1, keys[job.get_party_idx()], sid), 0);
  });

  std::vector<eckey::key_share_mp_t> out;
  const buf_t chain_code = crypto::gen_random(32);
  dylog_disable_scope_t no_log_err;

  EXPECT_NE(normal_derive_mp(keys[0], crypto::gen_random(31), {path({0})}, out), 0);
  EXPECT_NE(normal_derive_mp(keys[0], chain_code, {}, out), 0);
  EXPECT_NE(normal_derive_mp(keys[0], chain_code, {path({})}, out), 0);
  EXPECT_NE(normal_derive_mp(keys[0], chain_code, {path({0x80000000u})}, out), 0);
  EXPECT_NE(normal_derive_mp(keys[0], chain_code, {path({0}), path({0})}, out), 0);

  // A null chain code with a plausible size must be rejected before use.
  EXPECT_NE(normal_derive_mp(keys[0], mem_t(nullptr, 32), {path({0})}, out), 0);

  // BIP-32 depth is one byte: 255 levels is the most a path can have.
  {
    bip32_path_t too_deep;
    for (int i = 0; i < 256; i++) too_deep.append(0);
    EXPECT_NE(normal_derive_mp(keys[0], chain_code, {too_deep}, out), 0);
  }

  // Bound the number of paths derived in one call.
  {
    std::vector<bip32_path_t> too_many;
    for (uint32_t i = 0; i < 257; i++) too_many.push_back(path({i}));
    EXPECT_NE(normal_derive_mp(keys[0], chain_code, too_many, out), 0);
  }

  eckey::key_share_mp_t broken = keys[0];
  broken.Q += broken.curve.generator();
  EXPECT_NE(normal_derive_mp(broken, chain_code, {path({0})}, out), 0);

  broken = keys[0];
  MODULO(broken.curve.order()) broken.x_share = broken.x_share + 1;
  EXPECT_NE(normal_derive_mp(broken, chain_code, {path({0})}, out), 0);
}

}  // namespace
