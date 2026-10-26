# PhishGuard v1.0

An AI-assisted phishing-email detector. It analyzes an `.eml` file in **three parts**
and returns a single verdict: **SAFE**, **SUSPICIOUS**, or **PHISHING**.

```
         ┌─────────────────────── PhishGuard ───────────────────────┐
  .eml → │  HEADER            LINKS              CONTENT             │ → verdict
         │  (Envelope Checker) (Link Checker)    (Message Reader)    │
         └───────────────────────────────────────────────────────────┘
```

## The modules

| Part     | Module                 | What it checks                                   | Built by |
|----------|------------------------|--------------------------------------------------|----------|
| Header   | `auth_results`         | SPF / DKIM / DMARC failures                      | core     |
| Header   | `reply_to_mismatch`    | From domain vs Reply-To domain                   | **Bilal** |
| Header   | `brand_name_spoofing`  | Brand in display name vs real sender domain      | **Bilal** |
| Links    | `link_analysis`        | Raw-IP / shortener / look-alike / mismatch URLs  | **Bilal** |
| Links    | `virustotal`           | Checks each URL's reputation on VirusTotal        | **Bilal** |
| Content  | `content_ml`           | ML "Word Weigher" (Logistic Regression) on body  | ML       |

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Run

```bash
phishguard samples/phishing_sample.eml          # human-readable report
phishguard samples/safe_sample.eml
phishguard samples/phishing_sample.eml --json    # machine-readable
# or:  python -m phishguard.cli <file.eml>
```

## Web interface (upload & detect)

PhishGuard ships with a local web UI: upload a `.eml` file and see the verdict
(SAFE / SUSPICIOUS / PHISHING) with the reason from every module.

```bash
pip install flask
phishguard-web                 # then open http://127.0.0.1:5000
# or:  python -m phishguard.web
# change the port:  PHISHGUARD_PORT=8080 phishguard-web
```

To enable live VirusTotal checks in the UI, set your key before starting it:

```bash
export VT_API_KEY="your_virustotal_key"
phishguard-web
```

## Scoring

Each failed module adds risk points (WARNING=2, HIGH=3, CRITICAL=5).
Total >= 5 -> PHISHING, >= 2 -> SUSPICIOUS, else SAFE. Tune in `phishguard/core/engine.py`.

## The content model

`content_ml` loads `phishguard/content/word_weigher.pkl` if present; otherwise it
trains one from `phishguard/content/phishing_dataset.csv` on first run and caches it.
Retrain any time:

```bash
cd phishguard/content && python train_content.py
```

## VirusTotal module

The `virustotal` module checks every URL in the email against the VirusTotal v3 API
(malicious / suspicious engine counts). A URL VirusTotal marks malicious makes the
verdict PHISHING on its own (CRITICAL). It needs an API key and `requests`:

```bash
pip install requests
export VT_API_KEY="your_virustotal_key"      # get a free key at virustotal.com
# or pass it per-run:
phishguard samples/phishing_sample.eml --vt-key your_virustotal_key
```

Without a key (or without network) the module **skips cleanly** and the offline
`link_analysis` heuristics still run. **Never hard-code your API key in the source** -
always use VT_API_KEY or --vt-key. Free tier allows 4 requests/minute.

## Tests

```bash
pip install pytest
pytest -q
```
