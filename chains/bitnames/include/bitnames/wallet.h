// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// BitNames wallet, key-compatible with the plain-bitnames fork v0.18.2 (lib/wallet):
//   seed (BIP-39, tiny-bip39) -> master = BIP32-Ed25519 XPrv from sha256(seed), re-hashed
//   until from_nonextended_noforce accepts it (chain code = sha256(0x01 || secret));
//   tx signing keys m/0'/i, encryption keys m/1'/i, message signing keys m/2'/i (V2
//   derivation); a FROST key is kL reduced mod L, an x25519 secret is kL as is.
// Addresses start at index 0. Reservation nonces are keyed_hash(blake3(sk scalar), name).
// Their LMDB wallet is not read: import by mnemonic (set_seed_from_mnemonic or
// --mnemonic-seed-phrase-path) restores the same keys and addresses.
#pragma once

#include <bitnames/node.h>

#include <bt/ed25519_bip32.h>
#include <bt/kv.h>

#include <map>
#include <memory>
#include <mutex>
#include <set>

namespace bitnames {

struct Balance {
    uint64_t total = 0, available = 0;
};

struct WalletError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Wallet {
public:
    Wallet(const std::string& path, Node& node);
    bool has_seed();
    /** set_seed: error if a different seed exists. */
    void set_seed(const bt::ByteArray<64>& seed);
    void set_seed_from_mnemonic(const std::string& mnemonic);

    Address get_new_address();
    /** The last address, or a new one once the last has received (get_receive_address). */
    Address get_receive_address();
    std::vector<Address> addresses(); // sorted by base58
    bt::ByteArray<32> get_new_encryption_key();
    bt::frost::Point get_new_verifying_key();
    /** XVerifyingKey of m/0' (base58check "BNsXVK..."), XEncryptionSecretKey of m/1'. */
    std::string master_xvk();
    std::string master_xesk();

    std::vector<std::pair<OutPoint, FilledOutput>> utxos();
    std::vector<std::pair<OutPoint, SpentOutput>> stxos();
    Balance balance();

    Transaction create_transfer(const Address& dest, uint64_t value, uint64_t fee, const Bytes& memo);
    Transaction create_transfer_many(const std::map<Address, uint64_t>& dests, uint64_t fee);
    Transaction create_withdrawal(const bt::btc::Address& main_address, uint64_t value, uint64_t main_fee, uint64_t fee);
    /** reserve_bitname: like theirs, plus (policy) one value input with full change when the
     *  wallet has a coin, so the reservation's txid is unique and cannot be replayed. */
    Transaction reserve_bitname(const std::string& plain_name);
    Transaction register_bitname(const std::string& plain_name, const MutableBitNameData& data);
    AuthorizedTransaction authorize(const Transaction& tx);

    bt::frost::Signature sign_arbitrary_msg(const bt::frost::Point& vk, const std::string& msg);
    Authorization sign_arbitrary_msg_as_addr(const Address& a, const std::string& msg);
    Bytes decrypt_msg(const bt::ByteArray<32>& epk, ByteSpan ciphertext);
    std::optional<std::string> plain_name(const Hash32& name);

    // key derivation (exposed for tests and differential checks)
    static bt::ed25519_bip32::XPrv master_xprv(const bt::ByteArray<64>& seed);
    static bt::frost::SigningKey tx_signing_key(const bt::ByteArray<64>& seed, uint32_t index);
    static bt::frost::SigningKey message_signing_key(const bt::ByteArray<64>& seed, uint32_t index);
    static bt::ByteArray<32> encryption_secret(const bt::ByteArray<64>& seed, uint32_t index);

private:
    std::unique_ptr<bt::kv::Store> store_;
    Node& node_;
    std::mutex mu_;
    std::optional<bt::ByteArray<64>> seed();
    bt::ByteArray<64> need_seed();
    std::optional<uint32_t> index_of(uint8_t table, ByteSpan key);
    bt::frost::SigningKey key_for_address(const Address& a);
    std::set<OutPoint> pending_inputs();
    std::pair<uint64_t, std::vector<std::pair<OutPoint, FilledOutput>>> select_coins(uint64_t value);
    bool is_mine(const Address& a);
};

} // namespace bitnames
