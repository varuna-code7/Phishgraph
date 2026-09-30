import csv, difflib
import networkx as nx
from .url_features import _ext, LEET, TRUSTED

GENERIC = {"www", "com", "net", "org", "co", "in", "the", "my", "online", ""}


def tokens(d):
    return {t.translate(LEET) for t in _ext(d).domain.split("-") if t not in GENERIC}


class ThreatGraph:
    """Domain graph: known-bad seeds + every email analysed. Risk flows along edges."""

    def __init__(self, seed_path):
        self.g, self.bad, self.seen = nx.Graph(), set(), {}
        clusters = {}
        with open(seed_path) as f:
            for r in csv.DictReader(f):
                d = r["domain"].strip().lower()
                self._add(d, bad=True)
                clusters.setdefault(r["cluster"], []).append(d)
        for ds in clusters.values():
            for i in range(len(ds)):
                for j in range(i + 1, len(ds)):
                    self.g.add_edge(ds[i], ds[j], w=.9, kind="same campaign")

    def _add(self, d, bad=False):
        if d not in self.g:
            self.g.add_node(d)
        if bad:
            self.bad.add(d)

    def _link_similar(self, d):
        t = tokens(d)
        for b in list(self.bad):
            if b == d:
                continue
            shared = t & tokens(b)
            ratio = difflib.SequenceMatcher(None, d, b).ratio()
            w = max(min(.85, .5 + .15 * len(shared)) if len(shared) >= 2 else 0,
                    ratio * .9 if ratio >= .8 else 0)
            if w:
                self.g.add_edge(d, b, w=round(w, 2), kind="similar naming")

    def _risk(self, d):
        if d in self.bad:
            return 1.0, [f"{d} is a known phishing domain"]
        best, why, hits = 0.0, [], set()
        for n in self.g.neighbors(d):
            w1 = self.g[d][n]["w"]
            if n in self.bad:
                hits.add(n)
                if w1 > best:
                    best, why = w1, [f"{d} is closely linked to known phishing domain {n}"]
            for m in self.g.neighbors(n):
                if m in self.bad and m != d:
                    hits.add(m)
                    r = w1 * self.g[n][m]["w"]
                    if r > best:
                        best, why = r, [f"{d} connects to known phishing domain {m} via {n}"]
        if len(hits) >= 2:
            best = min(1.0, best + .1)
        return best, why

    def analyze(self, sender_domain, url_domains):
        doms = [d for d in dict.fromkeys([sender_domain] + url_domains) if d and d not in TRUSTED]
        reasons, score = [], 0.0
        for u in url_domains:  # campaign reuse: same link, many different senders
            others = self.seen.get(u, set()) - {sender_domain}
            if len(others) >= 2:
                score = max(score, .5)
                reasons.append(f"Link domain {u} already seen from {len(others)} other senders (possible campaign)")
        for d in doms:
            self._add(d)
        for u in url_domains:
            if u in doms and sender_domain in doms and u != sender_domain:
                self.g.add_edge(sender_domain, u, w=.8, kind="same email")
        for d in doms:
            self._link_similar(d)
        for d in doms:
            r, why = self._risk(d)
            r *= .7 if d == sender_domain and d not in url_domains else 1
            if r > 0:
                score = max(score, r); reasons += why
        for u in url_domains:
            self.seen.setdefault(u, set()).add(sender_domain)
        return min(score, 1.0), list(dict.fromkeys(reasons)), self.viz(doms, sender_domain, url_domains)

    def viz(self, doms, sender, urls):
        keep = set(doms)
        for d in doms:
            keep |= set(self.g.neighbors(d))
        keep = list(keep)[:30]
        nodes = [{"id": n, "label": n,
                  "group": "bad" if n in self.bad else "sender" if n == sender else "url" if n in urls else "other"}
                 for n in keep]
        edges = [{"from": a, "to": b, "label": self.g[a][b]["kind"]}
                 for a, b in self.g.subgraph(keep).edges()]
        return {"nodes": nodes, "edges": edges}

    def mark_bad(self, domains):
        for d in domains:
            self._add(d, bad=True)
        for i in range(len(domains)):
            for j in range(i + 1, len(domains)):
                self.g.add_edge(domains[i], domains[j], w=.9, kind="same campaign")
        for d in domains:
            self._link_similar(d)
