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
 *   x_share and only updates the public values. "First" is the smallest name
 *   in the ordered Qis map, not party index 0; it is deterministic for every
 *   party that holds the same Qis.
 * - Derived shares carry no chain code and no depth. Never feed a derived
 *   share back in: deriving from it with any chain code yields a
 *   self-consistent key that no BIP-32 wallet reproduces. Always derive from
 *   the root share with the full path.
 * - Stricter than BIP-32 on purpose: an index whose I_L is not below the curve
 *   order, or whose child point is infinity, is an error rather than "skip",
 *   so the cluster never signs for a key that btcec, bitcoinjs or scure would
 *   refuse to derive.
 */
error_t normal_derive_mp(const eckey::key_share_mp_t& key, mem_t chain_code,
                         const std::vector<bip32_path_t>& non_hardened_paths,
                         std::vector<eckey::key_share_mp_t>& derived_keys);

}  // namespace coinbase::mpc
