#include <cbmpc/core/precompiled.h>
#include <cbmpc/internal/crypto/base.h>
#include <cbmpc/internal/protocol/hd_keyset_mp.h>

namespace coinbase::mpc {

error_t normal_derive_mp(const eckey::key_share_mp_t& key, mem_t chain_code,
                         const std::vector<bip32_path_t>& non_hardened_paths,
                         std::vector<eckey::key_share_mp_t>& derived_keys) {
  derived_keys.clear();

  if (chain_code.size != 32) return coinbase::error(E_BADARG, "chain_code must be 32 bytes");
  if (key.Qis.empty()) return coinbase::error(E_BADARG, "missing Qis");
  if (key.Qis.find(key.party_name) == key.Qis.end()) return coinbase::error(E_BADARG, "party_name not in Qis");
  if (non_hardened_paths.empty()) return coinbase::error(E_BADARG, "no paths");
  if (bip32_path_t::has_duplicate(non_hardened_paths)) return coinbase::error(E_BADARG, "duplicate paths");
  for (const bip32_path_t& path : non_hardened_paths) {
    if (path.empty()) return coinbase::error(E_BADARG, "empty path");
    for (int j = 0; j < path.count(); j++) {
      if (path[j] & 0x80000000u) return coinbase::error(E_BADARG, "hardened index in non-hardened path");
    }
  }

  ecurve_t curve = key.curve;
  const auto& G = curve.generator();
  const mod_t& q = curve.order();

  if (key.x_share * G != key.Qis.at(key.party_name)) return coinbase::error(E_BADARG, "x_share does not match Qi");
  if (SUM(key.Qis) != key.Q) return coinbase::error(E_BADARG, "Q does not match the sum of Qis");

  // party_map_t is ordered by name, so every party picks the same one.
  const crypto::pname_t& first = key.Qis.begin()->first;
  std::vector<bn_t> delta = non_hard_derive(key.Q, chain_code, non_hardened_paths);

  int n = (int)non_hardened_paths.size();
  derived_keys.resize(n);
  for (int i = 0; i < n; i++) {
    eckey::key_share_mp_t& derived = derived_keys[i];
    derived = key;
    ecc_point_t delta_G = CBMPC_EVAL_VARTIME(delta[i] * G);
    derived.Q = key.Q + delta_G;
    derived.Qis[first] = key.Qis.at(first) + delta_G;
    if (key.party_name == first) {
      MODULO(q) derived.x_share = key.x_share + delta[i];
    }
  }

  return SUCCESS;
}

}  // namespace coinbase::mpc
