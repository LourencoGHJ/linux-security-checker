"""Local live dashboard. Collection runs in a background thread; HTTP binds to loopback."""
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PAGE = r"""<!doctype html><html lang="pt-PT"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GOLFINHO Live</title>
<style>
:root{color-scheme:dark;--bg:#071521;--panel:#102536;--line:#25465d;--text:#e8f4fb;--muted:#9bb2c2;--green:#51d6a0;--amber:#f0bd62;--red:#ff7777}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#123149 0,transparent 38%),var(--bg);color:var(--text);font:14px/1.55 Inter,"Segoe UI",Arial,sans-serif}
header{padding:24px 4vw;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}.brand{font-size:25px;font-weight:800;letter-spacing:2px}.muted,.sub{color:var(--muted)}
main{max-width:1500px;margin:24px auto;padding:0 3vw}.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
button,input{background:#0a1c2a;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px}button{cursor:pointer}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,.section{background:linear-gradient(145deg,var(--panel),#0d2030);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}.metric{font-size:28px;font-weight:750}.metric-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
.section{margin-top:14px}.section h2{font-size:16px;margin:0 0 12px}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:550px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-size:11px;text-transform:uppercase}.list{display:grid;gap:8px}.item{padding:10px;background:#0a1c2a;border:1px solid var(--line);border-radius:8px}.ok{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}.empty{color:var(--muted);padding:10px}.foot{padding:24px 0;color:var(--muted);font-size:12px}
@media(max-width:850px){.grid,.two{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.grid,.two{grid-template-columns:1fr}}
</style></head><body>
<header><div><div class="brand">GOLFINHO</div><div class="sub">Local Security Investigation Dashboard</div></div><div><strong id="connection" class="ok">A iniciar</strong><div id="lastUpdate" class="sub">À espera da primeira recolha</div></div></header>
<main><div class="toolbar"><div><strong id="host">Host local</strong><div id="platform" class="sub">A identificar o sistema...</div></div><div class="sub">UI: 1 s · Recolha: <b id="interval">5</b> s <button id="refresh">Recolher agora</button></div></div>
<div class="grid"><div class="card"><div class="metric-label">Interfaces</div><div id="interfacesCount" class="metric">—</div></div><div class="card"><div class="metric-label">Regras firewall</div><div id="rulesCount" class="metric">—</div></div><div class="card"><div class="metric-label">Ocorrências</div><div id="findingsCount" class="metric">—</div></div><div class="card"><div class="metric-label">Erros</div><div id="errorsCount" class="metric">—</div></div></div>
<div class="section"><h2>Sistema e fontes</h2><div class="two"><div id="system" class="list"></div><div id="sources" class="list"></div></div></div>
<div class="section"><h2>Interfaces de rede</h2><div class="table-wrap"><table><thead><tr><th>Interface</th><th>Tipo</th><th>Estado</th><th>MAC</th><th>Endereços</th></tr></thead><tbody id="networkRows"></tbody></table></div></div>
<div class="two"><div class="section"><h2>Gateways e DNS</h2><div id="routes" class="list"></div></div><div class="section"><h2>Perfis da firewall</h2><div class="table-wrap"><table><thead><tr><th>Perfil</th><th>Ativo</th><th>Entrada</th><th>Saída</th></tr></thead><tbody id="profilesRows"></tbody></table></div><div id="service" class="sub"></div></div></div>
<div class="section"><h2>Regras e filtros da firewall</h2><input id="ruleSearch" placeholder="Pesquisar regra, porta, endereço, aplicação..."><div class="table-wrap"><table><thead><tr><th>Regra</th><th>Direção</th><th>Ação</th><th>Perfil</th><th>Filtros</th></tr></thead><tbody id="rulesRows"></tbody></table></div></div>
<div class="section"><h2>Ocorrências</h2><div id="findings" class="list"></div></div>
<div class="section"><h2>Erros e verificações omitidas</h2><div class="two"><div id="errors" class="list"></div><div id="skipped" class="list"></div></div></div>
<div class="foot">Recolha read-only, local e sem transmissão externa. A interface atualiza a cada segundo; a recolha depende do intervalo configurado e da duração real das consultas do sistema.</div></main>
<script>
const $=id=>document.getElementById(id),arr=x=>Array.isArray(x)?x:[],esc=x=>String(x??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const item=(a,b)=>'<div class="item"><b>'+esc(a)+'</b>'+(b?'<div class="sub">'+esc(b)+'</div>':'')+'</div>';
function render(d){
const p=d.platform||{},n=d.network||{},f=d.firewall||{},ifs=arr(n.interfaces),rules=arr(f.enabled_rules),finds=arr(d.findings),errs=[...arr(d.errors),...arr(n.errors),...arr(f.errors)];
$("host").textContent=p.hostname||"Host local";$("platform").textContent=[p.name,p.version,p.architecture].filter(Boolean).join(" · ")||p.family||"Desconhecido";
$("interfacesCount").textContent=ifs.length;$("rulesCount").textContent=rules.length;$("findingsCount").textContent=finds.length;$("errorsCount").textContent=errs.length;
$("system").innerHTML=[["Sistema",p.name||p.family],["Versão / kernel",[p.version,p.kernel].filter(Boolean).join(" / ")],["Arquitetura",p.architecture],["Administrador",p.is_admin===true?"Sim":p.is_admin===false?"Não":"Desconhecido"],["Recolha",p.collection_mode||"read-only"]].map(x=>item(x[0],x[1])).join("");
const sources={...(n.sources||{}),...(f.sources||{})};$("sources").innerHTML=Object.entries(sources).map(x=>item(x[0],(x[1].status||"unknown")+(x[1].detail?" · "+x[1].detail:""))).join("")||'<div class="empty">Sem fontes reportadas</div>';
$("networkRows").innerHTML=ifs.map(x=>'<tr><td>'+esc(x.name)+'</td><td>'+esc(x.kind)+'</td><td>'+esc(x.is_up===true?"Ativa":x.is_up===false?"Inativa":"Desconhecido")+'</td><td>'+esc(x.mac)+'</td><td>'+esc(arr(x.addresses).map(a=>a.family+" "+a.address+"/"+(a.prefix_length??"?")).join(" · "))+'</td></tr>').join("")||'<tr><td colspan="5" class="empty">Sem interfaces</td></tr>';
const gw=arr(n.gateways).map(x=>item("Gateway "+x.family+": "+x.address,x.interface));const dns=arr(n.dns_servers).map(x=>{const a=arr(n.dns_server_analysis).find(y=>y.address===x);return item("DNS "+x,a?.classification)});$("routes").innerHTML=[...gw,...dns].join("")||'<div class="empty">Sem gateways ou DNS</div>';
$("profilesRows").innerHTML=arr(f.profiles).map(x=>'<tr><td>'+esc(x.name)+'</td><td>'+esc(x.enabled===true?"Sim":x.enabled===false?"Não":"?")+'</td><td>'+esc(x.default_inbound_action)+'</td><td>'+esc(x.default_outbound_action)+'</td></tr>').join("")||'<tr><td colspan="4" class="empty">Sem perfis</td></tr>';
const s=f.service||{};$("service").textContent=s.name?"Serviço "+s.name+": "+s.status+" · Arranque "+s.start_type:"Serviço não disponível";
$("rulesRows").innerHTML=rules.map(x=>{const z=[...arr(x.port_filters),...arr(x.address_filters),...arr(x.application_filters)].map(y=>JSON.stringify(y)).join(" · ");return '<tr><td>'+esc(x.display_name||x.name)+'</td><td>'+esc(x.direction)+'</td><td>'+esc(x.action)+'</td><td>'+esc(x.profile)+'</td><td>'+esc(z||"Sem filtros detalhados")+'</td></tr>'}).join("")||'<tr><td colspan="5" class="empty">Sem regras recolhidas</td></tr>';
$("findings").innerHTML=finds.map(x=>item((x.severity||"UNKNOWN")+" · "+(x.title||x.rule_id||"Finding"),(x.description||"")+" "+(x.recommendation||""))).join("")||'<div class="empty">Sem ocorrências pelas regras disponíveis</div>';
$("errors").innerHTML=errs.map(x=>item(x.check||x.source||"Erro",x.error)).join("")||'<div class="ok">Sem erros</div>';$("skipped").innerHTML=arr(d.checks_skipped).map(x=>item(x.check,x.reason)).join("")||'<div class="empty">Sem verificações omitidas</div>';filterRules();
}
function filterRules(){const q=$("ruleSearch").value.toLowerCase();document.querySelectorAll("#rulesRows tr").forEach(x=>x.style.display=x.innerText.toLowerCase().includes(q)?"":"none")}
let busy=false;async function refresh(){if(busy)return;busy=true;try{const r=await fetch("/api/snapshot",{cache:"no-store"});if(!r.ok)throw Error("HTTP "+r.status);const s=await r.json();if(s.data){render(s.data);$("lastUpdate").textContent="Última recolha: "+new Date(s.updated_at).toLocaleString()+" · idade "+s.age_seconds.toFixed(1)+" s · duração "+s.last_duration_seconds+" s";$("connection").textContent="Ligado · recolha ativa";$("interval").textContent=s.interval_seconds}else{$("connection").textContent="A recolher";$("lastUpdate").textContent=s.error||"Primeira recolha em curso"}}catch(e){$("connection").textContent="Ligação interrompida";$("connection").className="bad";$("lastUpdate").textContent=e.message}finally{busy=false}}
$("refresh").onclick=()=>fetch("/api/refresh",{method:"POST"}).finally(refresh);$("ruleSearch").addEventListener("input",filterRules);refresh();setInterval(refresh,1000);
</script></body></html>"""


class DashboardState:
    def __init__(self, interval_seconds):
        self.interval_seconds = interval_seconds
        self.lock = threading.Lock()
        self.collect_lock = threading.Lock()
        self.data = None
        self.updated_at = None
        self.error = None
        self.last_duration_seconds = None
        self.stop_event = threading.Event()
        self.thread = None

    def collect_once(self):
        with self.collect_lock:
            started = time.monotonic()
            try:
                from golfinho.engine.scanner import run_security_scan
                data = run_security_scan()
                error = None
            except Exception as exc:
                data, error = None, str(exc)
            timestamp = datetime.now(timezone.utc).isoformat()
            with self.lock:
                if data is not None:
                    self.data, self.updated_at, self.error = data, timestamp, None
                else:
                    self.error = error
                self.last_duration_seconds = round(time.monotonic() - started, 3)

    def start(self):
        def worker():
            while not self.stop_event.is_set():
                started = time.monotonic()
                self.collect_once()
                self.stop_event.wait(max(0, self.interval_seconds - (time.monotonic() - started)))
        self.thread = threading.Thread(target=worker, name="golfinho-collector", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)

    def snapshot(self):
        with self.lock:
            age = None if not self.updated_at else round(
                (datetime.now(timezone.utc) - datetime.fromisoformat(self.updated_at)).total_seconds(), 3)
            return {"data": self.data, "updated_at": self.updated_at, "age_seconds": age,
                    "interval_seconds": self.interval_seconds,
                    "last_duration_seconds": self.last_duration_seconds, "error": self.error}


def serve_dashboard(port=8765, interval_seconds=5, open_browser=True):
    if not 1 <= interval_seconds <= 3600:
        raise ValueError("interval_seconds must be between 1 and 3600.")
    state = DashboardState(interval_seconds)
    state.start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return
        def send_body(self, status, body, content_type):
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(encoded)
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                self.send_body(200, PAGE, "text/html; charset=utf-8")
            elif path == "/api/snapshot":
                self.send_body(200, json.dumps(state.snapshot(), ensure_ascii=False, default=str),
                               "application/json; charset=utf-8")
            else:
                self.send_body(404, '{"error":"not found"}', "application/json")
        def do_POST(self):
            if urlparse(self.path).path == "/api/refresh":
                threading.Thread(target=state.collect_once, daemon=True).start()
                self.send_body(202, '{"accepted":true}', "application/json")
            else:
                self.send_body(404, '{"error":"not found"}', "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:{}/".format(server.server_address[1])
    print("GOLFINHO live dashboard: " + url)
    print("Collection interval: {}s | UI refresh: 1s | read-only | loopback only".format(interval_seconds))
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping GOLFINHO dashboard...")
    finally:
        server.shutdown()
        server.server_close()
        state.stop()
