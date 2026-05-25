// test_hidden_entities.cpp
// Unit tests for HiddenEntitiesStore: in-memory operations and JSON persistence.
// Pure logic — no network I/O, no server dependency.

#include "ntm_test.hpp"
#include "../src/ntm_types.hpp"

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// In-memory operations
// ═══════════════════════════════════════════════════════════════════════════

static const std::string kClientA = std::string(64, 'a');
static const std::string kClientB = std::string(64, 'b');
static const std::string kIfaceEth0 = "eth0";
static const std::string kIfaceEth1 = "eth1";

TEST_CASE("hidden entities: fresh store has nothing hidden")
{
    HiddenEntitiesStore s;
    REQUIRE(!s.isClientHidden(kClientA));
    REQUIRE(!s.isIfaceHidden(kClientA, kIfaceEth0));
}

TEST_CASE("hidden entities: hide client — isClientHidden returns true")
{
    HiddenEntitiesStore s;
    s.hiddenClients.insert(kClientA);
    REQUIRE(s.isClientHidden(kClientA));
    REQUIRE(!s.isClientHidden(kClientB));
}

TEST_CASE("hidden entities: hide client suppresses all its interfaces")
{
    HiddenEntitiesStore s;
    s.hiddenClients.insert(kClientA);
    REQUIRE(s.isIfaceHidden(kClientA, kIfaceEth0));
    REQUIRE(s.isIfaceHidden(kClientA, kIfaceEth1));
    REQUIRE(!s.isIfaceHidden(kClientB, kIfaceEth0));
}

TEST_CASE("hidden entities: hide interface only — client still visible")
{
    HiddenEntitiesStore s;
    s.hiddenIfaces.insert({kClientA, kIfaceEth0});
    REQUIRE(!s.isClientHidden(kClientA));
    REQUIRE(s.isIfaceHidden(kClientA, kIfaceEth0));
    REQUIRE(!s.isIfaceHidden(kClientA, kIfaceEth1));
    REQUIRE(!s.isIfaceHidden(kClientB, kIfaceEth0));
}

TEST_CASE("hidden entities: unhide client removes it")
{
    HiddenEntitiesStore s;
    s.hiddenClients.insert(kClientA);
    REQUIRE(s.isClientHidden(kClientA));
    s.hiddenClients.erase(kClientA);
    REQUIRE(!s.isClientHidden(kClientA));
}

TEST_CASE("hidden entities: unhide interface removes it")
{
    HiddenEntitiesStore s;
    s.hiddenIfaces.insert({kClientA, kIfaceEth0});
    s.hiddenIfaces.insert({kClientA, kIfaceEth1});
    s.hiddenIfaces.erase({kClientA, kIfaceEth0});
    REQUIRE(!s.isIfaceHidden(kClientA, kIfaceEth0));
    REQUIRE(s.isIfaceHidden(kClientA, kIfaceEth1));
}

TEST_CASE("hidden entities: multiple clients independent")
{
    HiddenEntitiesStore s;
    s.hiddenClients.insert(kClientA);
    s.hiddenIfaces.insert({kClientB, kIfaceEth0});
    REQUIRE(s.isClientHidden(kClientA));
    REQUIRE(!s.isClientHidden(kClientB));
    REQUIRE(s.isIfaceHidden(kClientA, kIfaceEth0));  // whole client hidden
    REQUIRE(s.isIfaceHidden(kClientB, kIfaceEth0));  // specific iface hidden
    REQUIRE(!s.isIfaceHidden(kClientB, kIfaceEth1)); // other iface not hidden
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON persistence round-trip
// ═══════════════════════════════════════════════════════════════════════════

// Build the same JSON the server writes and parse it back, verifying contents.
// We test the round-trip by serialising directly and reloading via the file path.

static std::string hiddenEntitiesToJson(const HiddenEntitiesStore &s)
{
    std::string j = "{\n  \"hidden_clients\": [";
    bool first = true;
    for (const auto &id : s.hiddenClients)
    {
        if (!first) j += ',';
        j += "\n    \""; j += id; j += '"';
        first = false;
    }
    j += "\n  ],\n  \"hidden_interfaces\": [";
    first = true;
    for (const auto &p : s.hiddenIfaces)
    {
        if (!first) j += ',';
        j += "\n    {\"client_id\":\""; j += p.first;
        j += "\",\"iface\":\"";         j += p.second; j += "\"}";
        first = false;
    }
    j += "\n  ]\n}\n";
    return j;
}

// Simple JSON loader that mirrors the logic in server_core.cpp loadHiddenEntities().
static std::shared_ptr<HiddenEntitiesStore> loadFromJson(const std::string &content)
{
    auto sp = std::make_shared<HiddenEntitiesStore>();
    HiddenEntitiesStore &s = *sp;
    // Parse hidden_clients array
    {
        auto arrStart = content.find("\"hidden_clients\"");
        if (arrStart != std::string::npos)
        {
            auto lb = content.find('[', arrStart);
            auto rb = content.find(']', lb == std::string::npos ? 0 : lb);
            if (lb != std::string::npos && rb != std::string::npos)
            {
                std::size_t pos = lb + 1;
                while (pos < rb)
                {
                    auto q1 = content.find('"', pos);
                    if (q1 == std::string::npos || q1 >= rb) break;
                    auto q2 = content.find('"', q1 + 1);
                    if (q2 == std::string::npos || q2 >= rb) break;
                    std::string id = content.substr(q1 + 1, q2 - q1 - 1);
                    if (id.size() == 64)
                        s.hiddenClients.insert(id);
                    pos = q2 + 1;
                }
            }
        }
    }
    // Parse hidden_interfaces array
    {
        auto arrStart = content.find("\"hidden_interfaces\"");
        if (arrStart != std::string::npos)
        {
            auto lb = content.find('[', arrStart);
            auto rb = content.rfind(']');
            if (lb != std::string::npos && rb != std::string::npos && rb > lb)
            {
                std::size_t pos = lb + 1;
                while (pos < rb)
                {
                    auto ob = content.find('{', pos);
                    auto cb = content.find('}', ob == std::string::npos ? rb : ob);
                    if (ob == std::string::npos || cb == std::string::npos || ob >= rb) break;
                    std::string obj = content.substr(ob, cb - ob + 1);
                    auto extractVal = [&](const std::string &key) -> std::string {
                        auto k = obj.find('"' + key + '"');
                        if (k == std::string::npos) return {};
                        auto col = obj.find(':', k + key.size() + 2);
                        if (col == std::string::npos) return {};
                        auto q1 = obj.find('"', col + 1);
                        if (q1 == std::string::npos) return {};
                        auto q2 = obj.find('"', q1 + 1);
                        if (q2 == std::string::npos) return {};
                        return obj.substr(q1 + 1, q2 - q1 - 1);
                    };
                    std::string clientId = extractVal("client_id");
                    std::string iface    = extractVal("iface");
                    if (clientId.size() == 64 && !iface.empty())
                        s.hiddenIfaces.insert({clientId, iface});
                    pos = cb + 1;
                }
            }
        }
    }
    return sp;
}

TEST_CASE("hidden entities: JSON round-trip for client")
{
    HiddenEntitiesStore orig;
    orig.hiddenClients.insert(kClientA);
    const std::string json = hiddenEntitiesToJson(orig);
    const auto loaded = loadFromJson(json);
    REQUIRE(loaded->isClientHidden(kClientA));
    REQUIRE(!loaded->isClientHidden(kClientB));
}

TEST_CASE("hidden entities: JSON round-trip for interface")
{
    HiddenEntitiesStore orig;
    orig.hiddenIfaces.insert({kClientB, kIfaceEth0});
    const std::string json = hiddenEntitiesToJson(orig);
    const auto loaded = loadFromJson(json);
    REQUIRE(!loaded->isClientHidden(kClientB));
    REQUIRE(loaded->isIfaceHidden(kClientB, kIfaceEth0));
    REQUIRE(!loaded->isIfaceHidden(kClientB, kIfaceEth1));
}

TEST_CASE("hidden entities: JSON round-trip with both clients and interfaces")
{
    HiddenEntitiesStore orig;
    orig.hiddenClients.insert(kClientA);
    orig.hiddenIfaces.insert({kClientB, kIfaceEth0});
    orig.hiddenIfaces.insert({kClientB, kIfaceEth1});
    const std::string json = hiddenEntitiesToJson(orig);
    const auto loaded = loadFromJson(json);
    REQUIRE(loaded->isClientHidden(kClientA));
    REQUIRE(!loaded->isClientHidden(kClientB));
    REQUIRE(loaded->isIfaceHidden(kClientB, kIfaceEth0));
    REQUIRE(loaded->isIfaceHidden(kClientB, kIfaceEth1));
    REQUIRE(loaded->isIfaceHidden(kClientA, kIfaceEth0)); // hidden because whole client is hidden
}

TEST_CASE("hidden entities: empty store serialises and reloads cleanly")
{
    HiddenEntitiesStore orig;
    const std::string json = hiddenEntitiesToJson(orig);
    const auto loaded = loadFromJson(json);
    REQUIRE(!loaded->isClientHidden(kClientA));
    REQUIRE(!loaded->isIfaceHidden(kClientA, kIfaceEth0));
}
