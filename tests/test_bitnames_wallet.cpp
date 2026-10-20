// Wallet key derivation: the plain-bitnames fork's chain (sha256 master + BIP32-Ed25519 V2
// m/0'/i, m/1'/i, m/2'/i). Cross-checks against their wallet are differential test 7.
#include "test.h"

#include <bitnames/wallet.h>

#include <bt/ecies.h>
#include <bt/hd.h>

#include <cstring>

using namespace bitnames;

TEST(wallet_derivation_chain)
{
    auto phrase = bt::hd::parse_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    REQUIRE(phrase.has_value());
    auto seed = bt::hd::mnemonic_to_seed(*phrase);
    auto m = Wallet::master_xprv(seed);
    CHECK((m.b[0] & 7) == 0);
    CHECK((m.b[31] & 0xe0) == 0x40); // clamped, 3rd highest bit clear (noforce)
    auto k0 = Wallet::tx_signing_key(seed, 0), k1 = Wallet::tx_signing_key(seed, 1);
    CHECK(!(k0.s == k1.s));
    // the FROST key is kL of m/0'/i reduced mod L
    auto x = m.derive(0x80000000u).derive(0);
    bt::ByteArray<64> wide{};
    std::memcpy(wide.data(), x.b.data(), 32);
    CHECK(bt::frost::reduce_wide(wide) == k0.s);
    // encryption secrets are distinct x25519 keys; ECIES round trips through them
    auto e0 = Wallet::encryption_secret(seed, 0);
    auto ct = bt::ecies::encrypt(bt::ecies::x25519_public(e0), bt::ByteSpan((const uint8_t*)"hi", 2));
    auto pt = bt::ecies::decrypt(e0, ct);
    REQUIRE(pt.has_value());
    CHECK(std::string(pt->begin(), pt->end()) == "hi");
    // message keys live under m/2'
    CHECK(!(Wallet::message_signing_key(seed, 0).s == k0.s));
    std::fprintf(stderr, "  address[0] %s address[1] %s\n", address_from_vk(k0.verifying_key()).to_base58().c_str(),
                 address_from_vk(k1.verifying_key()).to_base58().c_str());
}
