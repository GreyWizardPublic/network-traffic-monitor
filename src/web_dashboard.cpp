// web_dashboard.cpp — HTTPS dashboard: HTTP routes, JSON API, embedded HTML/CSS/JS.
// Edit this file to change the web UI or add API endpoints.
// The only dependency on server internals is TrafficStats::snapshot() via ntm_types.hpp.

#include "web_dashboard.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ntm
{

// ---------------------------------------------------------------------------
// LAN guard
// ---------------------------------------------------------------------------

// Returns true if ip (IPv4 or IPv6 string) is in RFC 1918 / loopback / ULA /
// link-local space. Non-parseable strings return false (reject).
static bool isLanIP(const std::string &ip)
{
    struct in_addr a4;
    if (::inet_pton(AF_INET, ip.c_str(), &a4) == 1)
    {
        std::uint32_t a = ntohl(a4.s_addr);
        if ((a & 0xFF000000u) == 0x7F000000u) return true; // 127.0.0.0/8
        if ((a & 0xFF000000u) == 0x0A000000u) return true; // 10.0.0.0/8
        if ((a & 0xFFF00000u) == 0xAC100000u) return true; // 172.16.0.0/12
        if ((a & 0xFFFF0000u) == 0xC0A80000u) return true; // 192.168.0.0/16
        return false;
    }
    struct in6_addr a6;
    if (::inet_pton(AF_INET6, ip.c_str(), &a6) == 1)
    {
        static const std::uint8_t lo6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (std::memcmp(&a6, lo6, 16) == 0) return true;       // ::1
        if ((a6.s6_addr[0] & 0xFEu) == 0xFCu) return true;    // fc00::/7 ULA
        if (a6.s6_addr[0] == 0xFEu &&
            (a6.s6_addr[1] & 0xC0u) == 0x80u) return true;    // fe80::/10 link-local
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Per-IP sliding-window rate limiter
// ---------------------------------------------------------------------------

class WebRateLimiter
{
public:
    explicit WebRateLimiter(unsigned rpm) : rpm_(rpm) {}

    bool tryAcquire(const std::string &ip)
    {
        if (rpm_ == 0) return true;
        std::lock_guard<std::mutex> lk(mtx_);
        auto &dq = map_[ip];
        const auto now = std::chrono::steady_clock::now();
        while (!dq.empty() &&
               std::chrono::duration_cast<std::chrono::seconds>(now - dq.front()).count() >= 60)
            dq.pop_front();
        if (dq.size() >= rpm_) return false;
        dq.push_back(now);
        return true;
    }

private:
    unsigned rpm_;
    std::mutex mtx_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> map_;
};

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

// Escape a string for embedding in a JSON value (without surrounding quotes).
static std::string jsonEsc(const std::string &s)
{
    std::string o;
    o.reserve(s.size() + 4);
    for (unsigned char c : s)
    {
        if      (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 0x20)  ; // drop other control chars
        else                o += static_cast<char>(c);
    }
    return o;
}

static std::string buildSummaryJson(TrafficStats &stats, std::size_t maxEntityLines,
                                    const std::unordered_map<std::string, std::string> &nicknames)
{
    TrafficStats::InterfaceTotals totals;
    TrafficStats::InterfaceFlows flows;
    TrafficStats::InterfaceCountryFlows countryFlows;
    TrafficStats::InterfaceEntityFlows entityFlows;
    TrafficStats::TimePoint windowStart;
    stats.snapshot(totals, flows, countryFlows, entityFlows, &windowStart);

    // Returns the nickname for a client hex-id, or the hex-id itself if no nickname is set.
    auto displayClient = [&nicknames](const std::string &hexId) -> const std::string & {
        auto it = nicknames.find(hexId);
        return it != nicknames.end() ? it->second : hexId;
    };

    const auto windowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        windowStart.time_since_epoch()).count();
    const auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string j;
    j.reserve(4096);
    j += "{\n  \"window_start\": ";
    j += std::to_string(windowEpoch);
    j += ",\n  \"generated_at\": ";
    j += std::to_string(nowEpoch);

    // Interfaces
    j += ",\n  \"interfaces\": [";
    bool first = true;
    for (const auto &kv : totals)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(displayClient(client));
        j += "\",\"iface\":\"";
        j += jsonEsc(iface);
        j += "\",\"packets\":";
        j += std::to_string(kv.second.packets);
        j += ",\"bytes\":";
        j += std::to_string(kv.second.bytes);
        j += '}';
        first = false;
    }
    j += "\n  ]";

    // Entities — collect all rows, sort by bytes descending, truncate
    struct EntityRow
    {
        std::string client, iface, srcEntity, dstEntity;
        std::uint64_t packets{0}, bytes{0};
    };
    std::vector<EntityRow> rows;
    for (const auto &kv : entityFlows)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        for (const auto &ek : kv.second)
            rows.push_back({client, iface, ek.first.src, ek.first.dst,
                            ek.second.packets, ek.second.bytes});
    }
    std::sort(rows.begin(), rows.end(),
              [](const EntityRow &a, const EntityRow &b) { return a.bytes > b.bytes; });
    bool truncated = false;
    if (maxEntityLines > 0 && rows.size() > maxEntityLines)
    {
        rows.resize(maxEntityLines);
        truncated = true;
    }

    j += ",\n  \"entities\": [";
    first = true;
    for (const auto &r : rows)
    {
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(displayClient(r.client));
        j += "\",\"iface\":\"";
        j += jsonEsc(r.iface);
        j += "\",\"packets\":";
        j += std::to_string(r.packets);
        j += ",\"bytes\":";
        j += std::to_string(r.bytes);
        j += ",\"src_entity\":\"";
        j += jsonEsc(r.srcEntity);
        j += "\",\"dst_entity\":\"";
        j += jsonEsc(r.dstEntity);
        j += "\"}";
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated\": ";
    j += truncated ? "true" : "false";
    j += "\n}\n";
    return j;
}

// ---------------------------------------------------------------------------
// Embedded dashboard HTML/CSS/JS
// ---------------------------------------------------------------------------

static const char kDashboardHtml[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Monitor</title>
<style>
*{box-sizing:border-box}
body{font-family:monospace;background:#0e0e14;color:#ccc;margin:0;padding:16px}
h1{font-size:1.05em;margin:0 0 4px;color:#7af}
.meta{font-size:0.78em;color:#666;margin-bottom:14px}
.section{color:#7af;font-size:0.82em;text-transform:uppercase;letter-spacing:.06em;margin:18px 0 4px}
table{border-collapse:collapse;width:100%;font-size:0.82em;margin-bottom:4px}
th{background:#161622;color:#888;text-align:left;padding:5px 10px;border-bottom:1px solid #252535;white-space:nowrap}
td{padding:3px 10px;border-bottom:1px solid #1a1a28;white-space:nowrap}
tr:hover td{background:#171726}
.note{font-size:0.75em;color:#666;margin-top:2px}
#status{font-size:0.75em;margin-bottom:10px}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle}
.ok{background:#3a3}
.err{background:#a33}
.trunc{color:#a80;font-style:italic;font-size:0.8em;padding:4px 10px}
</style>
</head>
<body>
<h1>Network Traffic Monitor</h1>
<div id="status"><span id="dot" class="dot ok"></span><span id="smsg">Loading&#8230;</span></div>
<div class="meta">
  Window start: <span id="win">&#8212;</span> &nbsp;|&nbsp;
  Updated: <span id="gen">&#8212;</span> &nbsp;|&nbsp;
  Auto-refresh: 30 s
</div>

<div class="section">Interfaces</div>
<table><thead><tr><th>Client</th><th>Interface</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody id="iface_body"></tbody></table>
<div class="note" id="iface_note"></div>

<div class="section">Entity Flows <span style="color:#555;font-size:0.85em">(sorted by bytes, top results)</span></div>
<table><thead><tr><th>Client</th><th>Interface</th><th>Src Entity</th><th>Dst Entity</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody id="entity_body"></tbody></table>
<div class="note" id="entity_note"></div>

<script>
const POLL_MS=30000;
function fmtB(b){
  if(b<1024)return b+'B';
  if(b<1048576)return(b/1024).toFixed(1)+'K';
  if(b<1073741824)return(b/1048576).toFixed(1)+'M';
  return(b/1073741824).toFixed(2)+'G';
}
function fmtT(ep){return ep?new Date(ep*1000).toLocaleString():'—';}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function row(cells){return'<tr>'+cells.map(c=>'<td>'+esc(c)+'</td>').join('')+'</tr>';}
async function refresh(){
  try{
    const r=await fetch('/api/summary',{cache:'no-store'});
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    document.getElementById('win').textContent=fmtT(d.window_start);
    document.getElementById('gen').textContent=fmtT(d.generated_at);
    const ifaces=d.interfaces||[];
    document.getElementById('iface_body').innerHTML=
      ifaces.length?ifaces.map(x=>row([x.client||'(ip-auth)',x.iface,
        x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
      :'<tr><td colspan="4" style="color:#555">No data yet</td></tr>';
    document.getElementById('iface_note').textContent='';
    const ents=d.entities||[];
    document.getElementById('entity_body').innerHTML=
      ents.length?ents.map(x=>row([x.client||'(ip-auth)',x.iface,
        x.src_entity,x.dst_entity,x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
      :'<tr><td colspan="6" style="color:#555">No data yet</td></tr>';
    document.getElementById('entity_note').textContent=
      d.truncated?'Results truncated to server limit.':'';
    setS(true,'OK — '+new Date().toLocaleTimeString());
  }catch(e){setS(false,'Error: '+e.message);}
}
function setS(ok,m){
  document.getElementById('dot').className='dot '+(ok?'ok':'err');
  document.getElementById('smsg').textContent=m;
}
refresh();
setInterval(refresh,POLL_MS);
</script>
</body>
</html>
)HTML";

// ---------------------------------------------------------------------------
// Web server thread
// ---------------------------------------------------------------------------

void webServerThread(httplib::SSLServer &svr,
                     TrafficStats &stats,
                     const WebConfig &config)
{
    WebRateLimiter rateLimiter(config.rate_limit_rpm);

    // Pre-routing: LAN check, rate limit, optional bearer token.
    svr.set_pre_routing_handler(
        [&](const httplib::Request &req, httplib::Response &res) -> httplib::Server::HandlerResponse
        {
            const std::string &ip = req.remote_addr;
            if (!isLanIP(ip))
            {
                res.status = 403;
                res.set_content("{\"error\":\"forbidden: LAN clients only\"}\n",
                                "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            if (!rateLimiter.tryAcquire(ip))
            {
                res.status = 429;
                res.set_header("Retry-After", "60");
                res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            if (!config.token.empty())
            {
                auto auth = req.get_header_value("Authorization");
                const std::string expected = "Bearer " + config.token;
                if (auth != expected)
                {
                    res.status = 401;
                    res.set_header("WWW-Authenticate", "Bearer realm=\"ntm\"");
                    res.set_content("{\"error\":\"unauthorized\"}\n", "application/json");
                    return httplib::Server::HandlerResponse::Handled;
                }
            }
            // Security headers on every response.
            res.set_header("X-Content-Type-Options", "nosniff");
            // The dashboard uses inline <style> and <script> blocks; both must be
            // permitted explicitly — default-src 'self' alone would block them.
            res.set_header("Content-Security-Policy",
                           "default-src 'self'; "
                           "script-src 'self' 'unsafe-inline'; "
                           "style-src 'self' 'unsafe-inline'");
            return httplib::Server::HandlerResponse::Unhandled;
        });

    // GET / — embedded dashboard HTML
    svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(kDashboardHtml, "text/html; charset=utf-8");
    });

    // GET /api/summary — JSON snapshot of aggregated traffic
    svr.Get("/api/summary",
        [&stats, &config](const httplib::Request &, httplib::Response &res) {
            res.set_header("Cache-Control", "no-store");
            res.set_content(buildSummaryJson(stats, config.max_entity_lines,
                                             config.client_nicknames),
                            "application/json");
        });

    // All other paths → 404
    svr.set_error_handler([](const httplib::Request &, httplib::Response &res) {
        if (res.status == 404)
            res.set_content("{\"error\":\"not found\"}\n", "application/json");
    });

    svr.listen(config.bind, static_cast<int>(config.port));
}

} // namespace ntm
