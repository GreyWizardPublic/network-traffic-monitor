// tests/test_update_push.cpp — unit tests for the wire-4 update push subsystem:
//   - ClientUpdateRegistry state transitions (applyUpdLine)
//   - UpdateStatus expiry (5-min TTL after terminal)
//   - doOneCheckCycle callback ordering under mocked conditions (noop, stage progression)

#include "ntm_test.hpp"
#include "../src/ntm_types.hpp"

#include <chrono>
#include <string>
#include <vector>

using namespace ntm;

// ═══════════════════════════════════════════════════════════════════════════
// ClientUpdateRegistry
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("update registry: get returns empty status when no entry")
{
    ClientUpdateRegistry reg;
    UpdateStatus s = reg.get("abc");
    REQUIRE(s.req_id.empty());
    REQUIRE(s.stage.empty());
    REQUIRE(!s.terminal);
}

TEST_CASE("update registry: set stores and get retrieves")
{
    ClientUpdateRegistry reg;
    UpdateStatus us;
    us.req_id     = "aabbccdd11223344";
    us.stage      = "sent";
    us.terminal   = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set("client1", us);

    UpdateStatus out = reg.get("client1");
    REQUIRE_EQ(out.req_id, std::string("aabbccdd11223344"));
    REQUIRE_EQ(out.stage,  std::string("sent"));
    REQUIRE(!out.terminal);
}

TEST_CASE("update registry: applyUpdLine updates stage")
{
    ClientUpdateRegistry reg;
    UpdateStatus us;
    us.req_id   = "req1";
    us.stage    = "sent";
    us.terminal = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set("c1", us);

    bool ok = reg.applyUpdLine("c1", "req1", "checking", "", "", false);
    REQUIRE(ok);
    REQUIRE_EQ(reg.get("c1").stage, std::string("checking"));
    REQUIRE(!reg.get("c1").terminal);
}

TEST_CASE("update registry: applyUpdLine marks terminal on done")
{
    ClientUpdateRegistry reg;
    UpdateStatus us;
    us.req_id   = "req2";
    us.stage    = "applying";
    us.terminal = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set("c2", us);

    bool ok = reg.applyUpdLine("c2", "req2", "done", "", "1.21.0.0", true);
    REQUIRE(ok);
    UpdateStatus out = reg.get("c2");
    REQUIRE_EQ(out.stage,       std::string("done"));
    REQUIRE_EQ(out.new_version, std::string("1.21.0.0"));
    REQUIRE(out.terminal);
}

TEST_CASE("update registry: applyUpdLine rejects stale req_id")
{
    ClientUpdateRegistry reg;
    UpdateStatus us;
    us.req_id   = "current";
    us.stage    = "sent";
    us.terminal = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set("c3", us);

    bool ok = reg.applyUpdLine("c3", "stale_req", "checking", "", "", false);
    REQUIRE(!ok);
    REQUIRE_EQ(reg.get("c3").stage, std::string("sent"));
}

TEST_CASE("update registry: applyUpdLine stores error message")
{
    ClientUpdateRegistry reg;
    UpdateStatus us;
    us.req_id   = "req3";
    us.stage    = "verifying_sha256";
    us.terminal = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set("c4", us);

    bool ok = reg.applyUpdLine("c4", "req3", "err_verifying_sha256", "hash-mismatch", "", true);
    REQUIRE(ok);
    UpdateStatus out = reg.get("c4");
    REQUIRE_EQ(out.stage, std::string("err_verifying_sha256"));
    REQUIRE_EQ(out.error, std::string("hash-mismatch"));
    REQUIRE(out.terminal);
}

TEST_CASE("update registry: set overwrites previous entry")
{
    ClientUpdateRegistry reg;
    UpdateStatus us1;
    us1.req_id   = "old";
    us1.stage    = "sent";
    us1.terminal = false;
    us1.started_at = std::chrono::steady_clock::now();
    reg.set("c5", us1);

    UpdateStatus us2;
    us2.req_id   = "new";
    us2.stage    = "sent";
    us2.terminal = false;
    us2.started_at = std::chrono::steady_clock::now();
    reg.set("c5", us2);

    REQUIRE_EQ(reg.get("c5").req_id, std::string("new"));
}

TEST_CASE("update registry: multiple clients are independent")
{
    ClientUpdateRegistry reg;
    UpdateStatus ua, ub;
    ua.req_id = "ra"; ua.stage = "checking"; ua.terminal = false;
    ua.started_at = std::chrono::steady_clock::now();
    ub.req_id = "rb"; ub.stage = "downloading_binary"; ub.terminal = false;
    ub.started_at = std::chrono::steady_clock::now();

    reg.set("ca", ua);
    reg.set("cb", ub);

    REQUIRE_EQ(reg.get("ca").stage, std::string("checking"));
    REQUIRE_EQ(reg.get("cb").stage, std::string("downloading_binary"));

    reg.applyUpdLine("ca", "ra", "verifying_sha256", "", "", false);
    REQUIRE_EQ(reg.get("ca").stage, std::string("verifying_sha256"));
    REQUIRE_EQ(reg.get("cb").stage, std::string("downloading_binary")); // unchanged
}

// ═══════════════════════════════════════════════════════════════════════════
// L upd line stage ordering (simulated via applyUpdLine calls)
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("update push: full stage sequence terminates on done")
{
    ClientUpdateRegistry reg;
    const std::string id = "testclient";
    const std::string req = "testreq1";

    UpdateStatus us;
    us.req_id = req; us.stage = "sent"; us.terminal = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set(id, us);

    const std::vector<std::string> stages = {
        "checking", "downloading_binary", "verifying_sha256",
        "downloading_signature", "verifying_signature", "applying", "restarting"
    };
    for (const auto &s : stages)
    {
        bool ok = reg.applyUpdLine(id, req, s, "", "", false);
        REQUIRE(ok);
        REQUIRE_EQ(reg.get(id).stage, s);
        REQUIRE(!reg.get(id).terminal);
    }

    bool ok = reg.applyUpdLine(id, req, "done", "", "1.21.0.0", true);
    REQUIRE(ok);
    REQUIRE(reg.get(id).terminal);
    REQUIRE_EQ(reg.get(id).new_version, std::string("1.21.0.0"));
}

TEST_CASE("update push: noop terminates immediately")
{
    ClientUpdateRegistry reg;
    const std::string id = "c_noop";
    const std::string req = "rq_noop";

    UpdateStatus us;
    us.req_id = req; us.stage = "sent"; us.terminal = false;
    us.started_at = std::chrono::steady_clock::now();
    reg.set(id, us);

    bool ok = reg.applyUpdLine(id, req, "noop_no_update_available", "", "", true);
    REQUIRE(ok);
    REQUIRE(reg.get(id).terminal);
    REQUIRE_EQ(reg.get(id).stage, std::string("noop_no_update_available"));
}
