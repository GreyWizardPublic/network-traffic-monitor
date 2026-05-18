// web_dashboard.cpp — HTTPS dashboard: HTTP routes, JSON API, embedded HTML/CSS/JS.
// Edit this file to change the web UI or add API endpoints.
// The only dependency on server internals is TrafficStats::snapshot() via ntm_types.hpp.

#include "web_dashboard.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/crypto.h>   // CRYPTO_memcmp

namespace ntm
{

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

// Extract a string field value from a flat JSON object body.
// Handles \" and \\ escapes. Returns empty string on parse failure.
static std::string jsonGetString(const std::string &json, const std::string &key)
{
    const std::string needle = "\"" + key + "\"";
    std::size_t pos = 0;
    while (pos < json.size())
    {
        auto found = json.find(needle, pos);
        if (found == std::string::npos) return {};
        pos = found + needle.size();
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
            ++pos;
        if (pos >= json.size() || json[pos] != ':') continue; // false match inside a value
        ++pos;
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
            ++pos;
        if (pos >= json.size() || json[pos] != '"') return {};
        ++pos;
        std::string result;
        while (pos < json.size())
        {
            char c = json[pos++];
            if (c == '"') return result;
            if (c == '\\' && pos < json.size())
            {
                char e = json[pos++];
                switch (e) {
                    case '"':  result += '"';  break;
                    case '\\': result += '\\'; break;
                    case '/':  result += '/';  break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    case 't':  result += '\t'; break;
                    default:   result += e;    break;
                }
            }
            else result += c;
        }
        return {};
    }
    return {};
}

// ---------------------------------------------------------------------------
// Summary JSON builder
// ---------------------------------------------------------------------------

static std::string buildSummaryJson(TrafficStats &stats, std::size_t maxEntityLines,
                                    const std::unordered_map<std::string, std::string> &nicknames,
                                    const std::shared_ptr<ClientRegistry> &registry)
{
    TrafficStats::InterfaceTotals totals;
    TrafficStats::InterfaceFlows flows;
    TrafficStats::InterfaceCountryFlows countryFlows;
    TrafficStats::InterfaceEntityFlows entityFlows;
    TrafficStats::TimePoint windowStart;
    stats.snapshot(totals, flows, countryFlows, entityFlows, &windowStart);

    // Display name for any stored identifier: 64-char hex pubkey → nickname (or hex);
    // raw LAN IP → "Local Devices" (main tab); ASN entity string → as-is.
    // Entity strings are resolved to stable hex client IDs at ingest time, so no
    // IP→display registry lookup is needed here.
    auto isHexClientId = [](const std::string &s) -> bool {
        if (s.size() != 64) return false;
        for (char c : s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    };
    // Detects external-IP-scoped LAN keys produced at ingest time: "@[{scope}]:{ip}".
    // scope is the client's public WAN IP (or "null" when unreachable).
    // Clients behind the same NAT share the same scope → their unknown devices merge.
    auto parseReporterScoped = [](const std::string &s,
                                   std::string *scope = nullptr,
                                   std::string *lanIp = nullptr) -> bool {
        if (s.size() < 5 || s[0] != '@' || s[1] != '[') return false;
        auto cb = s.find(']', 2);
        if (cb == std::string::npos || cb + 1 >= s.size() || s[cb + 1] != ':') return false;
        if (scope) *scope  = s.substr(2, cb - 2);
        if (lanIp) *lanIp  = s.substr(cb + 2);
        return true;
    };
    auto displayClient = [&nicknames, &isHexClientId](const std::string &s) -> std::string {
        if (isHexClientId(s)) {
            auto it = nicknames.find(s);
            return it != nicknames.end() ? it->second : s;
        }
        return s;
    };
    auto resolveEntityMain = [&](const std::string &s) -> std::string {
        if (isHexClientId(s)) {
            auto it = nicknames.find(s);
            return it != nicknames.end() ? it->second : s;
        }
        // External-IP-scoped unknown LAN device: "@[{scope}]:{ip}"
        // scope is the shared WAN IP; "null" means no internet was reachable.
        std::string scope;
        if (parseReporterScoped(s, &scope)) {
            if (scope == "null") return "LAN (no internet)";
            return "LAN (" + scope + ")";
        }
        if (isLanIP(s)) return "Local Devices";
        return s;
    };

    const auto windowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        windowStart.time_since_epoch()).count();
    const auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string j;
    j.reserve(8192);
    j += "{\n  \"window_start\": ";
    j += std::to_string(windowEpoch);
    j += ",\n  \"generated_at\": ";
    j += std::to_string(nowEpoch);

    // Interfaces — unchanged
    j += ",\n  \"interfaces\": [";
    bool first = true;
    for (const auto &kv : totals)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(displayClient(client));   // hex → nickname (or hex if no nickname)
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

    // Entity Summary: group raw stored entities by resolved display labels, merge, sort.
    struct SummaryKey
    {
        std::string client, iface, src, dst;
        bool operator==(const SummaryKey &o) const noexcept
        {
            return client == o.client && iface == o.iface && src == o.src && dst == o.dst;
        }
    };
    struct SummaryKeyHash
    {
        std::size_t operator()(const SummaryKey &k) const noexcept
        {
            std::hash<std::string> h;
            return ((h(k.client) * 2654435761u) ^ (h(k.iface) * 40503u))
                 ^ ((h(k.src)    * 1315423911u) ^ h(k.dst));
        }
    };
    std::unordered_map<SummaryKey, Counter, SummaryKeyHash> summaryGroups;

    // LAN Detail: per unidentified-LAN-IP in/out totals, aggregated across all clients/ifaces.
    struct LanStats { std::uint64_t outPkts{0}, outBytes{0}, inPkts{0}, inBytes{0}; };
    std::unordered_map<std::string, LanStats> lanMap;

    for (const auto &kv : entityFlows)
    {
        auto sep = kv.first.find('|');
        std::string client = sep == std::string::npos ? std::string{} : kv.first.substr(0, sep);
        std::string iface  = sep == std::string::npos ? kv.first : kv.first.substr(sep + 1);
        const std::string &dispCli = displayClient(client);

        for (const auto &ek : kv.second)
        {
            const std::string &storedSrc = ek.first.src;
            const std::string &storedDst = ek.first.dst;
            const std::uint64_t pkts  = ek.second.packets;
            const std::uint64_t bytes = ek.second.bytes;

            // Group by resolved display labels for the Entity Summary tab.
            auto &sg = summaryGroups[{dispCli, iface,
                                      resolveEntityMain(storedSrc),
                                      resolveEntityMain(storedDst)}];
            sg.packets += pkts;
            sg.bytes   += bytes;

            // Accumulate per-IP in/out for unidentified LAN IPs.
            // Known client IPs are stored as hex IDs at ingest time.
            // Unknown LAN devices use the reporter-scoped "@hex:ip" key format;
            // legacy raw LAN IPs (if any) are also included for backwards compatibility.
            const bool srcUnident = parseReporterScoped(storedSrc) || isLanIP(storedSrc);
            const bool dstUnident = parseReporterScoped(storedDst) || isLanIP(storedDst);
            if (srcUnident) { auto &ls = lanMap[storedSrc]; ls.outPkts += pkts; ls.outBytes += bytes; }
            if (dstUnident) { auto &ls = lanMap[storedDst]; ls.inPkts  += pkts; ls.inBytes  += bytes; }
        }
    }

    // Sort Entity Summary rows by bytes descending, truncate.
    struct SummaryRow { std::string client, iface, src, dst; std::uint64_t packets{0}, bytes{0}; };
    std::vector<SummaryRow> summaryRows;
    summaryRows.reserve(summaryGroups.size());
    for (const auto &kv : summaryGroups)
        summaryRows.push_back({kv.first.client, kv.first.iface,
                               kv.first.src,    kv.first.dst,
                               kv.second.packets, kv.second.bytes});
    std::sort(summaryRows.begin(), summaryRows.end(),
              [](const SummaryRow &a, const SummaryRow &b) { return a.bytes > b.bytes; });
    bool truncated = false;
    if (maxEntityLines > 0 && summaryRows.size() > maxEntityLines)
    {
        summaryRows.resize(maxEntityLines);
        truncated = true;
    }

    // Sort LAN Detail rows by total bytes descending, truncate.
    struct LanRow { std::string ip; std::uint64_t outPkts{0}, outBytes{0}, inPkts{0}, inBytes{0}; };
    std::vector<LanRow> lanRows;
    lanRows.reserve(lanMap.size());
    for (const auto &kv : lanMap)
        lanRows.push_back({kv.first,
                           kv.second.outPkts, kv.second.outBytes,
                           kv.second.inPkts,  kv.second.inBytes});
    std::sort(lanRows.begin(), lanRows.end(),
              [](const LanRow &a, const LanRow &b) {
                  return (a.outBytes + a.inBytes) > (b.outBytes + b.inBytes);
              });
    bool truncatedLan = false;
    if (maxEntityLines > 0 && lanRows.size() > maxEntityLines)
    {
        lanRows.resize(maxEntityLines);
        truncatedLan = true;
    }

    // Emit Entity Summary
    j += ",\n  \"entities\": [";
    first = true;
    for (const auto &r : summaryRows)
    {
        if (!first) j += ',';
        j += "\n    {\"client\":\"";
        j += jsonEsc(r.client);
        j += "\",\"iface\":\"";
        j += jsonEsc(r.iface);
        j += "\",\"packets\":";
        j += std::to_string(r.packets);
        j += ",\"bytes\":";
        j += std::to_string(r.bytes);
        j += ",\"src_entity\":\"";
        j += jsonEsc(r.src);
        j += "\",\"dst_entity\":\"";
        j += jsonEsc(r.dst);
        j += "\"}";
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated\": ";
    j += truncated ? "true" : "false";

    // Emit LAN Detail
    j += ",\n  \"entities_lan\": [";
    first = true;
    for (const auto &r : lanRows)
    {
        if (!first) j += ',';
        // Parse external-IP-scoped key "@[{scope}]:{ip}" if present; fall back to raw IP.
        std::string displayIp, reportedBy, scope;
        if (parseReporterScoped(r.ip, &scope, &displayIp)) {
            reportedBy = (scope == "null") ? "no internet" : scope;
        } else {
            displayIp  = r.ip;
            reportedBy = "";
        }
        j += "\n    {\"ip\":\"";
        j += jsonEsc(displayIp);
        j += "\",\"reported_by\":\"";
        j += jsonEsc(reportedBy);
        j += "\",\"out_packets\":";
        j += std::to_string(r.outPkts);
        j += ",\"out_bytes\":";
        j += std::to_string(r.outBytes);
        j += ",\"in_packets\":";
        j += std::to_string(r.inPkts);
        j += ",\"in_bytes\":";
        j += std::to_string(r.inBytes);
        j += '}';
        first = false;
    }
    j += "\n  ]";
    j += ",\n  \"truncated_lan\": ";
    j += truncatedLan ? "true" : "false";

    // Emit client health stats (snapshotted from shared registry under mutex).
    j += ",\n  \"client_health\": [";
    first = true;
    if (registry)
    {
        struct HealthSnap { std::string clientId; ClientHealthStats hs; };
        std::vector<HealthSnap> healthSnaps;
        {
            std::lock_guard<std::mutex> lk(registry->mtx);
            for (const auto &kv : registry->clientHealth)
                healthSnaps.push_back({kv.first, kv.second});
        }
        const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Format percentage as "N.NN" without floating point or snprintf.
        auto fmtPct = [](std::uint64_t num, std::uint64_t denom) -> std::string {
            if (denom == 0) return "0.00";
            std::uint64_t pct100 = (num * 10000ULL) / denom;
            std::string s = std::to_string(pct100 / 100);
            s += '.';
            std::uint64_t frac = pct100 % 100;
            if (frac < 10) s += '0';
            s += std::to_string(frac);
            return s;
        };

        for (const auto &snap : healthSnaps)
        {
            const auto &hs = snap.hs;
            const std::uint64_t pcapTotal = hs.pcapRecv + hs.pcapDrop;
            const bool stale = (hs.reportedAtSec >= 0) &&
                               ((nowSec - hs.reportedAtSec) > 90);
            if (!first) j += ',';
            j += "\n    {\"client\":\"";
            j += jsonEsc(displayClient(snap.clientId));
            j += "\",\"pcap_recv\":";
            j += std::to_string(hs.pcapRecv);
            j += ",\"pcap_drop\":";
            j += std::to_string(hs.pcapDrop);
            j += ",\"pcap_drop_pct\":\"";
            j += fmtPct(hs.pcapDrop, pcapTotal);
            j += "\",\"buf_drop\":";
            j += std::to_string(hs.bufDrop);
            j += ",\"buf_drop_pct\":\"";
            j += fmtPct(hs.bufDrop, hs.pcapRecv);
            j += "\",\"reported_at\":";
            j += std::to_string(hs.reportedAtSec);
            j += ",\"stale\":";
            j += stale ? "true" : "false";
            j += '}';
            first = false;
        }
    }
    j += "\n  ]";
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
.tabs{display:flex;gap:0;margin:8px 0 0}
.tab{padding:4px 14px;cursor:pointer;border:1px solid #252535;border-bottom:none;border-radius:3px 3px 0 0;font-size:0.82em;color:#666;background:#111118;font-family:monospace;outline:none}
.tab.active{color:#7af;background:#0e0e14;border-color:#3a3a5a}
.tabpanel{border-top:1px solid #252535;padding-top:4px}
.hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px}
.admin-lnk{font-size:0.78em;color:#7af;text-decoration:none;opacity:0.7}
.admin-lnk:hover{opacity:1}
</style>
</head>
<body>
<div class="hdr">
  <h1>Network Traffic Monitor</h1>
  <a href="/admin" class="admin-lnk">Admin</a>
</div>
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

<div class="section">Entity Flows</div>
<div class="tabs">
  <button class="tab active" id="tab-summary" onclick="showTab('summary')">Entity Summary</button>
  <button class="tab" id="tab-lan" onclick="showTab('lan')">LAN Detail</button>
</div>
<div id="sec-summary" class="tabpanel">
  <table><thead><tr><th>Client</th><th>Interface</th><th>Src Entity</th><th>Dst Entity</th><th>Packets</th><th>Bytes</th></tr></thead>
  <tbody id="entity_body"></tbody></table>
  <div class="note" id="entity_note"></div>
</div>
<div id="sec-lan" class="tabpanel" style="display:none">
  <table><thead><tr><th>LAN IP</th><th>Reported by</th><th>Out Packets</th><th>Out Bytes</th><th>In Packets</th><th>In Bytes</th></tr></thead>
  <tbody id="lan_body"></tbody></table>
  <div class="note" id="lan_note"></div>
</div>

<div class="section">Client Health</div>
<table><thead><tr><th>Client</th><th>pcap recv</th><th>kernel drop</th><th>buf drop</th><th>last report</th></tr></thead>
<tbody id="health_body"></tbody></table>
<div class="note" id="health_note"></div>

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
function showTab(name){
  ['summary','lan'].forEach(function(t){
    document.getElementById('tab-'+t).className='tab'+(t===name?' active':'');
    document.getElementById('sec-'+t).style.display=t===name?'':'none';
  });
}
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
    const ents=d.entities||[];
    document.getElementById('entity_body').innerHTML=
      ents.length?ents.map(x=>row([x.client||'(ip-auth)',x.iface,
        x.src_entity,x.dst_entity,x.packets.toLocaleString(),fmtB(x.bytes)])).join('')
      :'<tr><td colspan="6" style="color:#555">No data yet</td></tr>';
    document.getElementById('entity_note').textContent=
      d.truncated?'Results truncated to server limit.':'';
    const lans=d.entities_lan||[];
    document.getElementById('lan_body').innerHTML=
      lans.length?lans.map(x=>row([x.ip,x.reported_by||'—',
        x.out_packets.toLocaleString(),fmtB(x.out_bytes),
        x.in_packets.toLocaleString(),fmtB(x.in_bytes)])).join('')
      :'<tr><td colspan="6" style="color:#555">No unidentified LAN devices detected</td></tr>';
    document.getElementById('lan_note').textContent=
      d.truncated_lan?'Results truncated to server limit.':'';
    const health=d.client_health||[];
    document.getElementById('health_body').innerHTML=
      health.length?health.map(function(x){
        const pd=parseFloat(x.pcap_drop_pct);
        const bd=parseFloat(x.buf_drop_pct);
        const pdC=pd>1?'#c44':pd>0.1?'#c84':'#4c4';
        const bdC=bd>1?'#c44':bd>0.1?'#c84':'#4c4';
        const st=x.stale?' <span style="color:#666">(stale)</span>':'';
        return'<tr><td>'+esc(x.client)+st+'</td><td>'+
          x.pcap_recv.toLocaleString()+'</td><td style="color:'+pdC+'">'+
          x.pcap_drop.toLocaleString()+' ('+x.pcap_drop_pct+'%)</td><td style="color:'+bdC+'">'+
          x.buf_drop.toLocaleString()+' ('+x.buf_drop_pct+'%)</td><td>'+
          fmtT(x.reported_at)+'</td></tr>';
      }).join(''):'<tr><td colspan="5" style="color:#555">No health data yet</td></tr>';
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
// Embedded admin HTML/CSS/JS
// ---------------------------------------------------------------------------

static const char kAdminHtml[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NTM Admin</title>
<style>
*{box-sizing:border-box}
body{font-family:monospace;background:#0e0e14;color:#ccc;margin:0;padding:16px}
h1{font-size:1.05em;margin:0 0 4px;color:#7af}
.back{font-size:0.78em;color:#7af;text-decoration:none;opacity:0.7}
.back:hover{opacity:1}
.hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:14px}
.section{color:#7af;font-size:0.82em;text-transform:uppercase;letter-spacing:.06em;margin:18px 0 6px}
.sub{font-size:0.78em;color:#666;margin-bottom:10px}
table{border-collapse:collapse;width:100%;font-size:0.82em;margin-bottom:4px}
th{background:#161622;color:#888;text-align:left;padding:5px 10px;border-bottom:1px solid #252535;white-space:nowrap}
td{padding:4px 10px;border-bottom:1px solid #1a1a28;white-space:nowrap}
tr.selectable{cursor:pointer}
tr.selectable:hover td{background:#171726}
tr.selected td{background:#1a1a2e;color:#cce}
tr.selected td:first-child::before{content:'▶ ';color:#7af}
.panel{border:1px solid #3a3a5a;border-radius:4px;padding:16px;margin-top:14px;background:#0d0d1a}
.warn{color:#c84;font-size:0.88em;margin-bottom:10px}
.panel-title{font-size:0.9em;color:#cce;margin-bottom:10px}
.lbl{font-size:0.82em;color:#888;margin-bottom:4px}
.pwd-row{display:flex;align-items:center;gap:10px;margin-bottom:4px}
input[type=password]{background:#111118;border:1px solid #3a3a5a;color:#ccc;padding:5px 8px;font-family:monospace;font-size:0.85em;border-radius:3px;width:280px;outline:none}
input[type=password]:focus{border-color:#7af}
.btn-row{display:flex;gap:10px;margin-top:14px}
button{font-family:monospace;font-size:0.82em;padding:5px 14px;border-radius:3px;border:1px solid #3a3a5a;cursor:pointer;outline:none}
.btn-cancel{background:#111118;color:#888}
.btn-cancel:hover{color:#ccc}
.btn-purge{background:#3a1010;color:#c84;border-color:#5a2020}
.btn-purge:hover{background:#4a1818;color:#f96}
.btn-purge:disabled{opacity:0.5;cursor:default}
.err-msg{font-size:0.8em;color:#c44}
.ok-panel{border:1px solid #2a5a2a;border-radius:4px;padding:16px;margin-top:14px;background:#0a150a}
.ok-title{color:#4c4;font-size:0.9em;margin-bottom:6px}
.ok-sub{font-size:0.8em;color:#666;margin-bottom:12px}
.btn-back{background:#111118;color:#7af;border-color:#3a3a5a}
.btn-back:hover{color:#adf}
#msg{font-size:0.78em;color:#666;margin-top:6px}
</style>
</head>
<body>
<div class="hdr">
  <h1>Network Traffic Monitor &mdash; Admin</h1>
  <a href="/" class="back">&#8592; Back to Dashboard</a>
</div>

<div class="section">Manage Clients</div>
<div class="sub" id="list_sub">Select a client to purge all its historical traffic data.</div>

<table>
  <thead><tr><th>Client</th><th>Interfaces</th><th>Packets</th><th>Bytes</th></tr></thead>
  <tbody id="client_body"><tr><td colspan="4" style="color:#555">Loading&#8230;</td></tr></tbody>
</table>

<div id="confirm_panel" style="display:none" class="panel">
  <div class="warn">&#9888;&nbsp; This permanently deletes all historical traffic records for this client.
  Data will accumulate fresh from the next connection.</div>
  <div class="panel-title">Purge all data for: <span id="selected_name" style="color:#7af"></span></div>
  <div class="lbl">Admin password</div>
  <div class="pwd-row">
    <input type="password" id="pwd_field" placeholder="Enter admin password" autocomplete="off">
    <span class="err-msg" id="pwd_error"></span>
  </div>
  <div class="btn-row">
    <button class="btn-cancel" onclick="cancelSelect()">Cancel</button>
    <button class="btn-purge" id="purge_btn" onclick="doPurge()">Purge Client Data</button>
  </div>
</div>

<div id="result_panel" style="display:none" class="ok-panel">
  <div class="ok-title">&#10003;&nbsp; <span id="result_client"></span> &mdash; data purged successfully.</div>
  <div class="ok-sub">Data will accumulate fresh from the next client connection.</div>
  <div class="btn-row">
    <button class="btn-back" onclick="resetView()">Back to client list</button>
  </div>
</div>

<div id="msg"></div>

<script>
function fmtB(b){
  if(b<1024)return b+'B';
  if(b<1048576)return(b/1024).toFixed(1)+'K';
  if(b<1073741824)return(b/1048576).toFixed(1)+'M';
  return(b/1073741824).toFixed(2)+'G';
}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
let selectedClient=null;

async function loadClients(){
  try{
    const r=await fetch('/api/summary',{cache:'no-store'});
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    const clients={};
    for(const x of (d.interfaces||[])){
      const name=x.client||'(ip-auth)';
      if(!clients[name])clients[name]={ifaces:[],packets:0,bytes:0};
      clients[name].ifaces.push(x.iface);
      clients[name].packets+=x.packets;
      clients[name].bytes+=x.bytes;
    }
    const tbody=document.getElementById('client_body');
    const names=Object.keys(clients);
    if(!names.length){
      tbody.innerHTML='<tr><td colspan="4" style="color:#555">No clients have recorded data yet</td></tr>';
      return;
    }
    tbody.innerHTML=names.map(name=>{
      const c=clients[name];
      return`<tr class="selectable" data-client="${esc(name)}">
        <td>${esc(name)}</td>
        <td>${esc(c.ifaces.join(', '))}</td>
        <td>${c.packets.toLocaleString()}</td>
        <td>${fmtB(c.bytes)}</td></tr>`;
    }).join('');
    tbody.querySelectorAll('tr').forEach(tr=>{
      tr.addEventListener('click',()=>selectClient(tr.dataset.client));
    });
    document.getElementById('msg').textContent='';
  }catch(e){
    document.getElementById('client_body').innerHTML=
      '<tr><td colspan="4" style="color:#a33">Error loading clients: '+esc(e.message)+'</td></tr>';
  }
}

function selectClient(name){
  selectedClient=name;
  document.querySelectorAll('#client_body tr').forEach(tr=>{
    tr.className=tr.dataset.client===name?'selectable selected':'selectable';
  });
  document.getElementById('selected_name').textContent=name;
  document.getElementById('confirm_panel').style.display='';
  document.getElementById('result_panel').style.display='none';
  document.getElementById('pwd_field').value='';
  document.getElementById('pwd_error').textContent='';
  document.getElementById('purge_btn').disabled=false;
  document.getElementById('purge_btn').textContent='Purge Client Data';
  document.getElementById('pwd_field').focus();
}

function cancelSelect(){
  selectedClient=null;
  document.querySelectorAll('#client_body tr').forEach(tr=>tr.className='selectable');
  document.getElementById('confirm_panel').style.display='none';
}

async function doPurge(){
  const pwd=document.getElementById('pwd_field').value;
  if(!pwd){document.getElementById('pwd_error').textContent='Password required';return;}
  const btn=document.getElementById('purge_btn');
  btn.disabled=true;btn.textContent='Purging…';
  document.getElementById('pwd_error').textContent='';
  try{
    const r=await fetch('/api/admin/purge',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd,client:selectedClient})
    });
    const d=await r.json();
    if(r.ok&&d.ok){
      document.getElementById('confirm_panel').style.display='none';
      document.getElementById('result_client').textContent=selectedClient;
      document.getElementById('result_panel').style.display='';
      loadClients();
    }else{
      document.getElementById('pwd_error').textContent=
        r.status===401?'✗ Incorrect password':
        r.status===404?'✗ Client not found':
        '✗ '+(d.error||'Unknown error');
      btn.disabled=false;btn.textContent='Purge Client Data';
    }
  }catch(e){
    document.getElementById('pwd_error').textContent='✗ Request failed: '+e.message;
    btn.disabled=false;btn.textContent='Purge Client Data';
  }
}

function resetView(){
  selectedClient=null;
  document.getElementById('result_panel').style.display='none';
  document.getElementById('confirm_panel').style.display='none';
  document.querySelectorAll('#client_body tr').forEach(tr=>tr.className='selectable');
  loadClients();
}

loadClients();
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
    // Separate, much stricter limiter for the admin purge endpoint.
    WebRateLimiter adminRateLimiter(5);

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

    // GET / — embedded monitoring dashboard HTML
    svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(kDashboardHtml, "text/html; charset=utf-8");
    });

    // GET /admin — embedded admin page (only registered when admin password is configured)
    if (!config.admin_password.empty())
    {
        svr.Get("/admin", [](const httplib::Request &, httplib::Response &res) {
            res.set_content(kAdminHtml, "text/html; charset=utf-8");
        });
    }

    // GET /api/summary — JSON snapshot of aggregated traffic
    svr.Get("/api/summary",
        [&stats, &config](const httplib::Request &, httplib::Response &res) {
            res.set_header("Cache-Control", "no-store");
            res.set_content(buildSummaryJson(stats, config.max_entity_lines,
                                             config.client_nicknames, config.registry),
                            "application/json");
        });

    // POST /api/admin/purge — erase one client's data (only registered when password is set)
    if (!config.admin_password.empty())
    {
        svr.Post("/api/admin/purge",
            [&stats, &config, &adminRateLimiter](const httplib::Request &req,
                                                  httplib::Response &res)
            {
                const std::string &ip = req.remote_addr;

                // Strict per-IP rate limit for the admin endpoint.
                if (!adminRateLimiter.tryAcquire(ip))
                {
                    res.status = 429;
                    res.set_header("Retry-After", "60");
                    res.set_content("{\"error\":\"rate limit exceeded\"}\n", "application/json");
                    return;
                }

                // Parse JSON body for password and client fields.
                const std::string &body = req.body;
                std::string password = jsonGetString(body, "password");
                std::string clientName = jsonGetString(body, "client");

                if (password.empty() || clientName.empty())
                {
                    res.status = 400;
                    res.set_content("{\"error\":\"bad request: password and client required\"}\n",
                                    "application/json");
                    return;
                }

                // Constant-time password comparison to prevent timing side-channels.
                const std::string &stored = config.admin_password;
                bool pwdOk = (password.size() == stored.size()) &&
                             (CRYPTO_memcmp(password.data(), stored.data(), stored.size()) == 0);
                if (!pwdOk)
                {
                    serverLog(LogLevel::Warn,
                              "ntm-server: admin purge REJECTED from %s (wrong password, client='%s')",
                              ip.c_str(), clientName.c_str());
                    res.status = 401;
                    res.set_content("{\"error\":\"unauthorized\"}\n", "application/json");
                    return;
                }

                // Resolve display name → hex client ID.
                // Try nickname reverse lookup first, then accept a raw 64-char hex ID directly.
                std::string hexId;
                for (const auto &kv : config.client_nicknames)
                {
                    if (kv.second == clientName) { hexId = kv.first; break; }
                }
                if (hexId.empty() && clientName.size() == 64)
                {
                    bool allHex = true;
                    for (char c : clientName)
                        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) { allHex=false; break; }
                    if (allHex) hexId = clientName;
                }
                // Also accept display name that equals the hex ID (no nickname configured).
                if (hexId.empty())
                {
                    for (const auto &kv : config.client_nicknames)
                        if (kv.first == clientName) { hexId = kv.first; break; }
                }
                if (hexId.empty())
                {
                    serverLog(LogLevel::Warn,
                              "ntm-server: admin purge from %s: client '%s' not found",
                              ip.c_str(), clientName.c_str());
                    res.status = 404;
                    res.set_content("{\"error\":\"client not found\"}\n", "application/json");
                    return;
                }

                bool hadData = stats.purgeClient(hexId);
                serverLog(LogLevel::Warn,
                          "ntm-server: admin purge from %s: client '%s' (id=%s) purged (%s)",
                          ip.c_str(), clientName.c_str(), hexId.c_str(),
                          hadData ? "data erased" : "no data was present");

                std::string resp = "{\"ok\":true,\"client_id\":\"";
                resp += jsonEsc(hexId);
                resp += "\",\"message\":\"client data purged\"}\n";
                res.set_content(resp, "application/json");
            });
    }

    // All other paths → 404
    svr.set_error_handler([](const httplib::Request &, httplib::Response &res) {
        if (res.status == 404)
            res.set_content("{\"error\":\"not found\"}\n", "application/json");
    });

    svr.listen(config.bind, static_cast<int>(config.port));
}

} // namespace ntm
