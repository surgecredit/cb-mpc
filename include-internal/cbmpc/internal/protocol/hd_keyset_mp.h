#pragma once
#include <cbmpc/internal/protocol/ec_dkg.h>
#include <cbmpc/internal/protocol/hd_tree_bip32.h>

namespace coinbase::mpc {

/**
 * @specs:
 * - mpc-friendly-derivation-spec | Normal-Derive-MP
 * @notes:
 * - Local computation, no communication.
 * - `key` must be an additive share: Q equals the sum of Qis. Threshold shares
 *   have to go through `to_additive_share` first.
 * - The first party by name absorbs the delta; every other party keeps its
 *   x_share and only updates the public values.
 */
error_t normal_derive_mp(const eckey::key_share_mp_t& key, mem_t chain_code,
                         const std::vector<bip32_path_t>& non_hardened_paths,
                         std::vector<eckey::key_share_mp_t>& derived_keys);

}  // namespace coinbase::mpc
