import re
from pathlib import Path

from . import nlp_model, url_features
from .graph_engine import ThreatGraph

PROJECT_ROOT = Path(__file__).resolve().parent.parent
graph = ThreatGraph(PROJECT_ROOT / "data" / "bad_domains.csv")
W = {"nlp": .4, "url": .3, "graph": .3}


def parse_sender(sender):
    m = re.search(r"<?([\w.+-]+)@([\w.-]+)>?", sender or "")
    display = re.sub(r"<.*", "", sender or "").strip().strip('"')
    return (m.group(2).lower() if m else ""), display


def analyze_email(sender, subject, body):
    text = f"{subject}\n{body}"
    sdom, display = parse_sender(sender)
    reasons = []

    p_nlp, terms = nlp_model.predict(text)
    if p_nlp > .5 and terms:
        reasons.append("Suspicious wording: " + ", ".join(terms))

    u = url_features.analyze_message(body)
    p_url = u["score"]
    reasons += u["reasons"]

    if sdom:
        s_score, s_rs, sreg = url_features.analyze_url("https://" + sdom)
        p_url = max(p_url, s_score * .8)
        reasons += [f"Sender: {r}" for r in s_rs]
        b = url_features.brand_imitated(display, sreg)
        if b and sreg not in url_features.TRUSTED:
            p_url = max(p_url, .6)
            reasons.append(f"Sender name says '{b}' but the address is @{sdom}")

    p_graph, g_rs, viz = graph.analyze(sdom, u["domains"])
    reasons += g_rs

    final = W["nlp"] * p_nlp + W["url"] * p_url + W["graph"] * p_graph
    if p_graph >= .9: final = max(final, .85)      # known-bad infrastructure
    elif p_url >= .7: final = max(final, .65)
    verdict = "Phishing" if final >= .6 else "Suspicious" if final >= .35 else "Safe"
    if verdict == "Safe" and not reasons:
        reasons.append("No risky wording, links or sender infrastructure found")
    return {"verdict": verdict, "score": round(final, 2),
            "scores": {"language": round(p_nlp, 2), "links": round(p_url, 2), "graph": round(p_graph, 2)},
            "reasons": reasons, "graph": viz, "domains": u["domains"] + ([sdom] if sdom else [])}


def report(domains):
    graph.mark_bad([d for d in domains if d not in url_features.TRUSTED])
