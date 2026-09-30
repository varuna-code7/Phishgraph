# PhishGraph

Real-time phishing detection that judges an email on three things at once: what it says, where its links lead, and who is behind the domains.

Built for problem statement PSN013: Real-Time AI Phishing Detection System using NLP and graph-based analysis.

## Why this exists

Keyword filters and blacklists miss brand-new domains, and AI-written phishing emails no longer have the spelling mistakes that used to give them away. PhishGraph combines three independent signals so an attacker has to fool all of them, not just one.

## How it works

```
Email (sender, subject, body)
        |
   Flask API
        |
  +-----+---------------------+
  |           |               |
Language    Link & sender    Graph
(NLP)       analysis         engine
  |           |               |
  +-----+---------------------+
        |
   Fusion (weighted score)
        |
Verdict: Safe / Suspicious / Phishing + reasons
```

**1. Language layer (`nlp_model.py`)**
TF-IDF with Logistic Regression. It scores intent (urgency, credential bait, impersonation) rather than typos. Text is normalised first, so zero-width characters and Unicode look-alikes don't hide anything. It also reports which words pushed the score up.

**2. Link and sender layer (`url_features.py`)**
Checks each link and the sender address for:
- brand look-alikes (`paypa1` vs `paypal`)
- link text that shows one domain but goes to another
- raw IP links, punycode characters, URL shorteners, odd top-level domains
- excessive hyphens, deep subdomains, `@` tricks, plain http
- display-name spoofing (sender name says a brand, address doesn't match)

**3. Graph layer (`graph_engine.py`)**
Domains are nodes. Edges connect domains that appear in the same email, share naming patterns, or belong to the same known campaign. Risk spreads along edges, so a brand-new domain linked to known phishing infrastructure gets flagged even though it has never been seen before. It also notices the same link arriving from many different senders.

**Fusion (`fusion.py`)**
Weighted blend: 40% language, 30% links, 30% graph. Strong evidence from the graph or link layer can override the blend. The result comes with plain-language reasons.

**Learning**
"Report as phishing" adds the email's domains to the graph, so later emails linked to them are caught.

## Project structure

```
phishguard/
  app.py             Flask routes
  nlp_model.py       train and predict
  url_features.py    link and sender checks
  graph_engine.py    domain graph and risk propagation
  fusion.py          combines scores, builds reasons
  requirements.txt
  data/
    bad_domains.csv  seed list of known phishing domains
  templates/
    index.html       web UI
```

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000 and use the three sample buttons: an obvious phish, an AI-written phish, and a legitimate email.

The graph view loads vis-network from a CDN, so it needs internet. Everything else runs offline.

## API

**POST /analyze**
```json
{ "sender": "IT Desk <it@example.co>", "subject": "Quick update", "body": "..." }
```
Returns the verdict, overall score, per-layer scores, reasons, the domain graph, and the domains found.

**POST /feedback**
```json
{ "domains": ["bad-domain.com"] }
```
Marks domains as phishing in the graph.

## Using your own data

- **Training data:** put a CSV at `data/emails.csv` with a text column and a label column (1 = phishing). Delete `model.joblib`, then run `python nlp_model.py`.
- **Known-bad domains:** add rows to `data/bad_domains.csv` (`domain,cluster`). Domains sharing a cluster are linked together. Feeds like PhishTank or OpenPhish are good sources.

## Current limitations

- The built-in training set is tiny and only for demonstration. Accuracy figures need a proper evaluation on a larger dataset.
- The seed list of known-bad domains is a small sample.
- Domain age and WHOIS checks are not included yet.
- The graph is held in memory and resets when the server restarts.

## Roadmap

- Transformer-based language model (DistilBERT)
- Live threat feeds (PhishTank, OpenPhish)
- Domain age and certificate features
- Landing-page screenshot comparison against brand logos
- Browser extension and Gmail add-on
- Persistent graph storage