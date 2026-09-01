#include <cbmpc/core/precompiled.h>
#include <cbmpc/internal/crypto/base.h>
#include <cbmpc/internal/protocol/hd_keyset_mp.h>

namespace coinbase::mpc {

namespace {

// BIP-32 serializes depth in one byte, so no valid path has more levels.
constexpr int MAX_PATH_DEPTH = 255;
// Bound the work a single call can request.
constexpr int MAX_PATHS_PER_CALL = 256;

// The additive tweak for one non-hardened path, with the two BIP-32 edge
// cases treated as errors instead of being silently reduced: a parsed I_L that
// is not below the curve order, and a child point at infinity. BIP-32 says to
// skip such an index; every wallet library we interoperate with (btcec,
// bitcoinjs, scure) throws on it, so the cluster must refuse it too or it would
// sign for a key no wallet can reproduce. Probability is about 2^-128 per step.
error_t strict_non_hard_delta(const ecc_point_t& Q, mem_t chain_code, const bip32_path_t& path,
                              const ecurve_t& curve, bn_t& delta) {
  const auto& G = curve.generator();
  const mod_t& q = curve.order();
  buf_t chain_code_temp = chain_code;
  ecc_point_t Q_temp = Q;
  delta = 0;
  for (int j = 0; j < path.count(); j++) {
    uint32_t index = path[j];
    buf_t I = coinbase::crypto::hmac_sha512_t(chain_code_temp).calculate(Q_temp, index);
    bn_t il = bn_t::from_bin(I.range(0, 32));
    if (il >= q) return coinbase::error(E_CRYPTO, "invalid child: I_L not below the curve order, skip this index");
    chain_code_temp = I.range(32, 32);
    Q_temp += il * G;
    if (Q_temp.is_infinity()) return coinbase::error(E_CRYPTO, "invalid child: point at infinity, skip this index");
    MODULO(q) delta = delta + il;
  }
  return SUCCESS;
}

}  // namespace

error_t normal_derive_mp(const eckey::key_share_mp_t& key, mem_t chain_code,
                         const std::vector<bip32_path_t>& non_hardened_paths,
                         std::vector<eckey::key_share_mp_t>& derived_keys) {
  // `key` may alias an element of `derived_keys` (chained derivation); copy it
  // before the output is cleared.
  const eckey::key_share_mp_t src = key;
  derived_keys.clear();

  if (chain_code.data == nullptr || chain_code.size != 32) {
    return coinbase::error(E_BADARG, "chain_code must be 32 bytes");
  }
  if (src.Qis.empty()) return coinbase::error(E_BADARG, "missing Qis");
  if (src.Qis.find(src.party_name) == src.Qis.end()) return coinbase::error(E_BADARG, "party_name not in Qis");
  if (non_hardened_paths.empty()) return coinbase::error(E_BADARG, "no paths");
  if ((int)non_hardened_paths.size() > MAX_PATHS_PER_CALL) return coinbase::error(E_BADARG, "too many paths");
  if (bip32_path_t::has_duplicate(non_hardened_paths)) return coinbase::error(E_BADARG, "duplicate paths");
  for (const bip32_path_t& path : non_hardened_paths) {
    if (path.empty()) return coinbase::error(E_BADARG, "empty path");
    if (path.count() > MAX_PATH_DEPTH) return coinbase::error(E_BADARG, "path too deep");
    for (int j = 0; j < path.count(); j++) {
      if (path[j] & 0x80000000u) return coinbase::error(E_BADARG, "hardened index in non-hardened path");
    }
  }

  ecurve_t curve = src.curve;
  const auto& G = curve.generator();
  const mod_t& q = curve.order();

  if (src.x_share * G != src.Qis.at(src.party_name)) return coinbase::error(E_BADARG, "x_share does not match Qi");
  if (SUM(src.Qis) != src.Q) return coinbase::error(E_BADARG, "Q does not match the sum of Qis");

  // party_map_t is ordered by name, so every party picks the same one.
  const crypto::pname_t& first = src.Qis.begin()->first;
  std::vector<bn_t> delta(non_hardened_paths.size());
  for (size_t i = 0; i < non_hardened_paths.size(); i++) {
    error_t rv = strict_non_hard_delta(src.Q, chain_code, non_hardened_paths[i], curve, delta[i]);
    if (rv) return rv;
  }

  int n = (int)non_hardened_paths.size();
  derived_keys.resize(n);
  for (int i = 0; i < n; i++) {
    eckey::key_share_mp_t& derived = derived_keys[i];
    derived = src;
    ecc_point_t delta_G = CBMPC_EVAL_VARTIME(delta[i] * G);
    derived.Q = src.Q + delta_G;
    derived.Qis[first] = src.Qis.at(first) + delta_G;
    if (src.party_name == first) {
      MODULO(q) derived.x_share = src.x_share + delta[i];
    }
  }

  return SUCCESS;
}

}  // namespace coinbase::mpc
