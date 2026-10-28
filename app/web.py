"""HTML pages (server rendered, no JavaScript framework)."""
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(default=True))

BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Breach Notice Agent</title>
<style>
:root{--bg:#f6f7f9;--fg:#1a1d21;--card:#fff;--line:#d9dde3;--accent:#0b5fff;--warn:#b42318;--ok:#067647}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--fg:#e8eaee;--card:#1d2127;--line:#343a43;--accent:#6e9bff;--warn:#ff8a80;--ok:#5dd39e}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:16px}
h1{font-size:1.4rem;margin:.2rem 0 1rem} h2{font-size:1.1rem;margin:1.2rem 0 .5rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
a{color:var(--accent)} table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;font-size:.9rem}
textarea,input[type=text]{width:100%;box-sizing:border-box;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px;font:inherit}
textarea{min-height:140px;font-family:ui-monospace,monospace;font-size:.85rem}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:8px 14px;font:inherit;cursor:pointer}
button.danger{background:var(--ok)} .tag{display:inline-block;padding:2px 8px;border-radius:99px;border:1px solid var(--line);font-size:.8rem}
.warn{color:var(--warn);font-weight:600} .ok{color:var(--ok);font-weight:600} code{font-size:.8rem;word-break:break-all}
</style></head><body><main>
<h1><a href="/" style="text-decoration:none;color:inherit">Breach Notice Agent</a> <span class="tag">GDPR Art. 33 / 34</span></h1>
{% block body %}{% endblock %}
</main></body></html>"""

INDEX = """{% extends base %}{% block body %}
<div class="card"><b>Ledger:</b> {% if verify.ok %}<span class="ok">chain intact, {{ verify.count }} entries</span>
{% else %}<span class="warn">BROKEN at entry {{ verify.broken_at }}: {{ verify.reason }}</span>{% endif %}
 | <a href="/ledger">view ledger</a></div>
<div class="card"><h2>New incident (synthetic data only)</h2>
<p>Load a sample: {% for s in samples %}<a href="/?sample={{ s }}">{{ s }}</a>{% if not loop.last %} | {% endif %}{% endfor %}</p>
<form method="post" action="/ui/incidents"><textarea name="payload" aria-label="Incident JSON">{{ payload }}</textarea>
{% if error %}<p class="warn">{{ error }}</p>{% endif %}
<p><button type="submit">Start 72 hour clock and assess</button></p></form></div>
<div class="card"><h2>Incidents</h2>
{% if rows %}<table><tr><th>ID</th><th>Title</th><th>Outcome</th><th>Status</th><th>Deadline</th></tr>
{% for r in rows %}<tr><td><a href="/incidents/{{ r.id }}">{{ r.id }}</a></td><td>{{ r.incident.title }}</td>
<td>{{ r.assessment.outcome }}</td><td>{{ r.status }}</td><td>{{ r.assessment.deadline }}</td></tr>{% endfor %}</table>
{% else %}<p>No incidents yet.</p>{% endif %}</div>{% endblock %}"""

DETAIL = """{% extends base %}{% block body %}
<div class="card"><h2>{{ s.incident.title }}</h2>
<p><code>{{ s.id }}</code> | status <span class="tag">{{ s.status }}</span> | breach type {{ s.incident.breach_type }}</p>
<p>Became aware: {{ s.incident.discovered_at }}<br>72 hour deadline: <b>{{ a.deadline }}</b><br>
{% if a.late %}<span class="warn">Deadline passed {{ (-a.hours_left)|round(1) }} h ago</span>
{% else %}<span class="ok">{{ a.hours_left|round(1) }} h left</span>{% endif %}</p></div>
<div class="card"><h2>Risk assessment: {{ a.outcome }} (score {{ a.score }})</h2>
<ul>{% for r in a.reasons %}<li>{{ r }}</li>{% endfor %}</ul>
{% if a.factors %}<table><tr><th>Factor</th><th>Points</th><th>Basis</th></tr>
{% for f in a.factors %}<tr><td>{{ f.name }}</td><td>{{ f.points }}</td><td>{{ f.basis }}</td></tr>{% endfor %}</table>{% endif %}</div>
{% if s.status == 'DRAFTED' %}
<form method="post" action="/incidents/{{ s.id }}/approve">
{% for key, d in s.drafts.items() %}<div class="card"><h2>{{ key }}</h2>
{% if d.subject %}<input type="text" name="subject__{{ key }}" value="{{ d.subject }}" aria-label="subject">{% endif %}
<textarea name="body__{{ key }}" aria-label="body {{ key }}">{{ d.body }}</textarea></div>{% endfor %}
<div class="card"><h2>Human approval</h2><p>Nothing is sent until the Data Protection Officer approves.</p>
<input type="text" name="approver" placeholder="DPO full name" required minlength="3">
<p><button type="submit">Approve drafts</button></p></div></form>
{% elif s.status in ('APPROVED', 'SEND_PARTIAL') %}
<div class="card"><p>Approved by <b>{{ s.approval.approved_by }}</b> at {{ s.approval.approved_at }}
(edited by human: {{ s.approval.edited_by_human }}).</p>
<form method="post" action="/incidents/{{ s.id }}/send"><button class="danger" type="submit">Send through Amazon SES</button></form></div>
{% endif %}
{% if s.sends %}<div class="card"><h2>Deliveries</h2><table><tr><th>Kind</th><th>Recipient ref</th><th>Result</th></tr>
{% for x in s.sends %}<tr><td>{{ x.kind }}</td><td><code>{{ x.to_ref }}</code></td>
<td>{% if x.ok %}<span class="ok">SES MessageId {{ x.message_id }}</span>{% else %}<span class="warn">{{ x.error }}</span>{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}
<div class="card"><h2>Evidence log for this incident</h2><table><tr><th>#</th><th>Time</th><th>Event</th><th>Hash</th></tr>
{% for e in log %}<tr><td>{{ e.seq }}</td><td>{{ e.ts }}</td><td>{{ e.event }}</td><td><code>{{ e.hash[:16] }}</code></td></tr>{% endfor %}</table></div>
{% endblock %}"""

LEDGER = """{% extends base %}{% block body %}
<div class="card"><h2>Evidence ledger (SHA-256 hash chain)</h2>
{% if verify.ok %}<p class="ok">Chain intact, {{ verify.count }} entries.</p>
{% else %}<p class="warn">BROKEN at entry {{ verify.broken_at }}: {{ verify.reason }}</p>{% endif %}
<table><tr><th>#</th><th>Time</th><th>Incident</th><th>Event</th><th>prev</th><th>hash</th></tr>
{% for e in rows %}<tr><td>{{ e.seq }}</td><td>{{ e.ts }}</td><td>{{ e.incident_id }}</td><td>{{ e.event }}</td>
<td><code>{{ e.prev_hash[:12] }}</code></td><td><code>{{ e.hash[:12] }}</code></td></tr>{% endfor %}</table></div>{% endblock %}"""


def render(template: str, **ctx) -> str:
    base = env.from_string(BASE)
    return env.from_string(template).render(base=base, **ctx)
