"""PhishGuard web interface — upload a .eml and get a verdict with reasons."""
import os
import math
import tempfile
from flask import Flask, request, render_template_string

from phishguard.core.engine import analyze_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB upload cap

# friendly names + the three-part grouping
FRIENDLY = {
    "auth_results": "SPF / DKIM / DMARC",
    "reply_to_mismatch": "Reply-To mismatch",
    "brand_name_spoofing": "Display-name spoofing",
    "link_analysis": "Suspicious links",
    "virustotal": "VirusTotal reputation",
    "content_ml": "Message text (AI)",
}
SECTION_ICON = {"Header": "✉", "Links": "🔗", "Content": "🧠"}
SECTIONS = [
    ("Header", "Envelope Checker", ["auth_results", "reply_to_mismatch", "brand_name_spoofing"]),
    ("Links", "Link Checker", ["link_analysis", "virustotal"]),
    ("Content", "Message Reader", ["content_ml"]),
]

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard — Cyber Email Analyzer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&family=Rajdhani:wght@500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#05070f; --bg2:#0a0f1e; --panel:rgba(17,27,46,.55); --line:rgba(56,189,248,.18);
    --txt:#e6f0ff; --muted:#8aa0c6; --cyan:#22d3ee; --green:#22c55e; --amber:#f59e0b;
    --red:#ff4d5e; --purple:#a78bfa;
    --disp:'Rajdhani',system-ui,sans-serif; --head:'Orbitron',system-ui,sans-serif;
    --mono:'JetBrains Mono',ui-monospace,Consolas,monospace;
    --body:'Rajdhani',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{
    background:var(--bg); color:var(--txt); font-family:var(--body);
    min-height:100vh; position:relative; overflow-x:hidden; letter-spacing:.3px;
  }
  /* layered cyber background: radial glows + grid + scanline */
  body::before{content:"";position:fixed;inset:0;z-index:-2;
    background:
      radial-gradient(900px 500px at 15% -10%, rgba(34,211,238,.14), transparent 60%),
      radial-gradient(800px 500px at 100% 0%, rgba(167,139,250,.12), transparent 55%),
      radial-gradient(700px 600px at 50% 120%, rgba(34,197,94,.10), transparent 60%),
      var(--bg);}
  body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.5;
    background-image:linear-gradient(rgba(56,189,248,.06) 1px,transparent 1px),
                     linear-gradient(90deg,rgba(56,189,248,.06) 1px,transparent 1px);
    background-size:44px 44px;
    -webkit-mask-image:radial-gradient(circle at 50% 30%,#000,transparent 85%);
            mask-image:radial-gradient(circle at 50% 30%,#000,transparent 85%);}
  .wrap{max-width:940px;margin:0 auto;padding:26px 18px 70px;position:relative}
  .scanbar{height:3px;border-radius:3px;margin-bottom:26px;
    background:linear-gradient(90deg,transparent,var(--cyan),var(--green),var(--purple),transparent);
    background-size:200% 100%;animation:slide 4s linear infinite;box-shadow:0 0 18px rgba(34,211,238,.6)}
  @keyframes slide{to{background-position:200% 0}}

  header.top{display:flex;align-items:center;gap:16px;margin-bottom:26px}
  .logo{width:56px;height:56px;border-radius:16px;flex:0 0 auto;display:flex;align-items:center;
    justify-content:center;font-size:28px;position:relative;
    background:linear-gradient(135deg,#0ea5e9,#22c55e);
    box-shadow:0 0 0 1px rgba(34,211,238,.5),0 0 30px rgba(34,211,238,.45);}
  .logo::after{content:"";position:absolute;inset:-4px;border-radius:18px;
    border:1px solid rgba(34,211,238,.35);animation:pulse 2.6s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:.3;transform:scale(1)}50%{opacity:.8;transform:scale(1.05)}}
  .brand h1{margin:0;font-family:var(--head);font-size:26px;font-weight:800;letter-spacing:2px;
    background:linear-gradient(90deg,#e6f0ff,#22d3ee);-webkit-background-clip:text;
    background-clip:text;-webkit-text-fill-color:transparent}
  .brand p{margin:3px 0 0;color:var(--muted);font-size:14px;font-family:var(--mono)}
  .brand .ver{color:var(--cyan)}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px;
    margin-bottom:18px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
    box-shadow:0 10px 40px rgba(0,0,0,.35)}

  /* dropzone */
  .drop{border:1.6px dashed rgba(34,211,238,.4);border-radius:16px;padding:34px 20px;text-align:center;
    background:linear-gradient(180deg,rgba(34,211,238,.04),transparent);transition:.2s;position:relative}
  .drop.drag{border-color:var(--cyan);background:rgba(34,211,238,.1);box-shadow:0 0 28px rgba(34,211,238,.25) inset}
  .drop .ic{font-size:40px;filter:drop-shadow(0 0 10px rgba(34,211,238,.5))}
  .drop h2{margin:10px 0 4px;font-family:var(--head);font-size:18px;letter-spacing:1px;font-weight:600}
  .drop p{margin:0 0 16px;color:var(--muted);font-size:14px;font-family:var(--mono)}
  .fname{color:var(--cyan);font-family:var(--mono);font-size:13px;min-height:18px;margin-top:10px;word-break:break-all}
  input[type=file]{display:none}
  .pick{display:inline-block;cursor:pointer;color:var(--txt);border:1px solid var(--line);
    background:rgba(34,211,238,.08);border-radius:10px;padding:10px 16px;font-family:var(--mono);font-size:13px}
  .pick:hover{border-color:var(--cyan);box-shadow:0 0 14px rgba(34,211,238,.25)}
  .btn{margin-top:18px;background:linear-gradient(135deg,#22d3ee,#22c55e);color:#04210f;font-weight:700;
    border:none;border-radius:12px;padding:13px 30px;font-size:16px;cursor:pointer;font-family:var(--disp);
    letter-spacing:1px;box-shadow:0 0 24px rgba(34,211,238,.4);transition:.15s}
  .btn:hover{filter:brightness(1.08);transform:translateY(-1px)}

  .err{background:rgba(255,77,94,.08);border:1px solid var(--red);color:#ffc9cf;border-radius:12px;
    padding:13px 16px;margin-bottom:18px;font-family:var(--mono);font-size:14px}

  /* verdict */
  .verdict{position:relative;overflow:hidden;border-radius:18px;padding:24px 26px;margin-bottom:20px;
    display:flex;align-items:center;justify-content:space-between;gap:20px;border:1.5px solid;
    backdrop-filter:blur(10px)}
  .verdict .lbl{font-size:12px;letter-spacing:4px;text-transform:uppercase;color:var(--muted);font-family:var(--mono)}
  .verdict .big{font-family:var(--head);font-size:40px;font-weight:800;margin-top:4px;letter-spacing:2px}
  .verdict .file{font-size:13px;color:var(--muted);margin-top:8px;font-family:var(--mono);word-break:break-all}
  .v-safe{background:rgba(34,197,94,.08);border-color:var(--green);box-shadow:0 0 40px rgba(34,197,94,.15)}
  .v-safe .big{color:var(--green);text-shadow:0 0 18px rgba(34,197,94,.6)}
  .v-susp{background:rgba(245,158,11,.08);border-color:var(--amber);box-shadow:0 0 40px rgba(245,158,11,.15)}
  .v-susp .big{color:var(--amber);text-shadow:0 0 18px rgba(245,158,11,.6)}
  .v-phish{background:rgba(255,77,94,.09);border-color:var(--red);box-shadow:0 0 50px rgba(255,77,94,.2)}
  .v-phish .big{color:var(--red);text-shadow:0 0 20px rgba(255,77,94,.7)}
  /* gauge ring */
  .ring{flex:0 0 auto;position:relative;width:118px;height:118px}
  .ring svg{transform:rotate(-90deg)}
  .ring .track{fill:none;stroke:rgba(255,255,255,.08);stroke-width:10}
  .ring .fill{fill:none;stroke-width:10;stroke-linecap:round;
    filter:drop-shadow(0 0 6px currentColor);transition:stroke-dashoffset 1s ease}
  .ring .mid{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
  .ring .mid .n{font-family:var(--head);font-size:30px;font-weight:800;line-height:1}
  .ring .mid .c{font-size:10px;letter-spacing:2px;color:var(--muted);font-family:var(--mono);margin-top:3px}

  .sec-title{font-family:var(--mono);font-size:12px;letter-spacing:2px;text-transform:uppercase;
    color:var(--cyan);margin:2px 2px 12px;font-weight:600;display:flex;align-items:center;gap:8px}
  .sec-title .ic{font-size:15px} .sec-title span{color:var(--muted);text-transform:none;letter-spacing:.5px}
  .row{display:flex;gap:14px;padding:14px 0;border-top:1px solid rgba(56,189,248,.1)}
  .row:first-of-type{border-top:none}
  .chip{flex:0 0 auto;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:1px;
    border-radius:8px;padding:6px 11px;height:fit-content;min-width:80px;text-align:center;border:1px solid}
  .c-pass{background:rgba(34,197,94,.12);color:#7ef0a6;border-color:#1f7a44;box-shadow:0 0 10px rgba(34,197,94,.2)}
  .c-warn{background:rgba(245,158,11,.12);color:#fcd34d;border-color:#946313;box-shadow:0 0 10px rgba(245,158,11,.2)}
  .c-high{background:rgba(255,77,94,.12);color:#ff99a3;border-color:#8a2b2b;box-shadow:0 0 10px rgba(255,77,94,.2)}
  .c-crit{background:rgba(255,77,94,.22);color:#ffc9cf;border-color:#c0392b;box-shadow:0 0 16px rgba(255,77,94,.4)}
  .c-info{background:rgba(138,160,198,.1);color:var(--muted);border-color:var(--line)}
  .row .name{font-weight:700;font-size:15.5px;margin-bottom:3px;font-family:var(--disp);letter-spacing:.4px}
  .row .why{color:var(--muted);font-size:14px;line-height:1.55;font-family:var(--mono);font-weight:400}
  footer{color:#4a5e82;font-size:12px;text-align:center;margin-top:30px;font-family:var(--mono);letter-spacing:1px}
  @media(max-width:580px){.verdict{flex-direction:column;align-items:flex-start}.brand h1{font-size:21px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="scanbar"></div>
  <header class="top">
    <div class="logo">🛡️</div>
    <div class="brand">
      <h1>PHISHGUARD</h1>
      <p>&gt; cyber email analyzer <span class="ver">v1.0</span> — header · links · content</p>
    </div>
  </header>

  <form class="card" action="/analyze" method="post" enctype="multipart/form-data" id="frm">
    <div class="drop" id="drop">
      <div class="ic">📡</div>
      <h2>DROP OR SELECT A .EML FILE</h2>
      <p>SPF/DKIM/DMARC · sender spoofing · links (+VirusTotal) · AI message scan</p>
      <label class="pick" for="eml">⬆ Choose file</label>
      <input type="file" name="eml" id="eml" accept=".eml" required>
      <div class="fname" id="fname"></div>
      <div><button class="btn" type="submit">▸ ANALYZE</button></div>
    </div>
  </form>

  {% if error %}<div class="err">⚠ {{ error }}</div>{% endif %}

  {% if result %}
    <div class="verdict {{ result.css }}">
      <div>
        <div class="lbl">Verdict</div>
        <div class="big">{{ result.verdict }}</div>
        <div class="file">📎 {{ filename }}</div>
      </div>
      <div class="ring" style="color:{{ result.ring_color }}">
        <svg width="118" height="118">
          <circle class="track" cx="59" cy="59" r="52"></circle>
          <circle class="fill" cx="59" cy="59" r="52"
            stroke="{{ result.ring_color }}"
            stroke-dasharray="326.7"
            stroke-dashoffset="{{ result.ring_offset }}"></circle>
        </svg>
        <div class="mid"><div class="n">{{ result.score }}</div><div class="c">RISK</div></div>
      </div>
    </div>

    {% for sec in result.sections %}
      <div class="card">
        <div class="sec-title"><span class="ic">{{ sec.icon }}</span>{{ sec.part }}
          <span>— {{ sec.nice }}</span></div>
        {% for it in sec.rows %}
          <div class="row">
            <div class="chip {{ it.cls }}">{{ it.badge }}</div>
            <div>
              <div class="name">{{ it.name }}</div>
              <div class="why">{{ it.why }}</div>
            </div>
          </div>
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}

  <footer>PHISHGUARD v1.0 · runs locally · header + links + content intelligence</footer>
</div>

<script>
  var drop=document.getElementById('drop'), inp=document.getElementById('eml'), fn=document.getElementById('fname');
  function show(){ if(inp.files && inp.files.length){ fn.textContent='✓ '+inp.files[0].name; } }
  inp.addEventListener('change', show);
  ['dragenter','dragover'].forEach(function(e){drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.add('drag');});});
  ['dragleave','drop'].forEach(function(e){drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.remove('drag');});});
  drop.addEventListener('drop', function(ev){ if(ev.dataTransfer.files.length){ inp.files=ev.dataTransfer.files; show(); } });
</script>
</body>
</html>
"""

BADGE_CLS = {"INFO": "c-info", "LOW": "c-info", "WARNING": "c-warn",
             "HIGH": "c-high", "CRITICAL": "c-crit"}
VERDICT_CSS = {"SAFE": "v-safe", "SUSPICIOUS": "v-susp", "PHISHING": "v-phish"}
RING_COLOR = {"SAFE": "#22c55e", "SUSPICIOUS": "#f59e0b", "PHISHING": "#ff4d5e"}
_CIRC = 2 * math.pi * 52  # ~326.7


def _build_result(reports, score, verdict):
    by = {r.module: r for r in reports}
    sections = []
    for part, nice, mods in SECTIONS:
        rows = []
        for m in mods:
            r = by.get(m)
            if not r:
                continue
            badge = "PASS" if r.passed else r.severity.name
            cls = "c-pass" if r.passed else BADGE_CLS.get(r.severity.name, "c-info")
            rows.append({"name": FRIENDLY.get(m, m), "why": r.details,
                         "badge": badge, "cls": cls})
        sections.append({"part": part, "nice": nice, "icon": SECTION_ICON.get(part, "•"), "rows": rows})
    gauge = min(score / 12.0, 1.0)              # 12+ risk fills the ring
    ring_offset = round(_CIRC * (1 - gauge), 1)
    return {"verdict": verdict, "score": score, "css": VERDICT_CSS.get(verdict, "v-susp"),
            "ring_color": RING_COLOR.get(verdict, "#f59e0b"), "ring_offset": ring_offset,
            "sections": sections}


@app.route("/", methods=["GET"])
def index():
    return render_template_string(PAGE, result=None, error=None, filename=None)


@app.route("/analyze", methods=["POST"])
def analyze():
    f = request.files.get("eml")
    if not f or f.filename == "":
        return render_template_string(PAGE, result=None, filename=None,
                                      error="Please choose a .eml file to analyze.")
    if not f.filename.lower().endswith(".eml"):
        return render_template_string(PAGE, result=None, filename=None,
                                      error="That doesn't look like a .eml file. Please upload an .eml email.")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".eml")
    try:
        f.save(tmp.name)
        tmp.close()
        reports, score, verdict = analyze_file(tmp.name)
    except Exception as e:
        return render_template_string(PAGE, result=None, filename=None,
                                      error=f"Could not analyze this email: {e}")
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
    result = _build_result(reports, score, verdict)
    return render_template_string(PAGE, result=result, error=None, filename=f.filename)


def main():
    port = int(os.environ.get("PHISHGUARD_PORT", "5000"))
    print(f"\n  PhishGuard web UI running at:  http://127.0.0.1:{port}\n  (press Ctrl+C to stop)\n")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
