#include "test.h"

#include <bitnames/types.h>

using namespace bitnames;

TEST(bitnames_empty_block_merkle_root)
{
    // every empty betanet block has merkle root 812c9708...bdbb (fork coinbase tree)
    auto r = compute_merkle_root(Coinbase{}, {});
    REQUIRE(r.has_value());
    CHECK_EQ(bt::hex_encode(*r), std::string("812c97082cde521a6128a777b45d9221259e8e3e33d6f84b7b496ef43ca6bdbb"));
}
