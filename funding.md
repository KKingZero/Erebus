# Erebus — Funding & Go-To-Market Plan

**Pricing model:** **$5,000 USD / month / organization** — includes **3–5 operator seats** (minimum **3 seats** to buy).

**Positioning:** First **AI-native** command-and-control framework where the operator states intent; Erebus plans, executes, and requests approval on high-risk actions — with full audit trail and human-in-the-loop control.

> For authorized security testing, red team engagements, and research only.

---

## 1. Executive summary

Erebus is not “a chatbot on top of Cobalt Strike.” The wedge is **intent-driven operations**: autonomous agent loops wired to real implant tasks, server-side approval gates, structured loot/results for the LLM, and `next_suggested_actions` chaining from recon output.

**Today:** Strong engineering foundation (~40% of a meeting-ready demo MVP; ~25–30% of a credible commercial product).

**Next 90 days:** Ship one **Golden Demo**, 3 design-partner pilots, and sell the **Team** plan at **$5k/mo** (3–5 seats).

**Funding ask (seed):** Attach this roadmap to a $1.5M–$3M seed narrative *after* 2–3 paid pilots or LOIs at **$2.5–5k/mo per org**.

---

## 2. Pricing: $5k / month / org (3–5 seats)

### One simple SKU

| | |
|---|---|
| **Price** | **$5,000 / month** |
| **Minimum** | **3 operator seats** (required to purchase) |
| **Included** | **Up to 5 operator seats** |
| **Billing** | Per organization (one teamserver, one contract) |

**Effective per seat (amortized):**

| Seats used | $/seat/month | $/seat/year |
|------------|--------------|-------------|
| 3 (min) | ~$1,667 | ~$20,000 |
| 4 | $1,250 | $15,000 |
| 5 (max included) | $1,000 | $12,000 |

Compare: Cobalt Strike ≈ **$3,500/year/seat** (~$290/mo). Erebus at full 5-seat bundle ≈ **3.4× CS per seat** — defensible as **AI-native team platform**, not a lone C2 license.

### What’s included in $5k/mo

| Included | Notes |
|----------|--------|
| Up to **5 named operators** | mTLS client cert per seat |
| **1 teamserver** | Shared per org |
| **AI agent** | BYO LLM key or bundled inference (pilot) |
| **Console + AI TUI** | Primary operator UX |
| **Approval workflow** | Server-side gates + operator approve/deny |
| **Audit log** | Per-operator actions (Phase 1+) |
| **Standard support** | Email / community; 48h SLA in Phase 2 |

### Above 5 seats

| Add-on | Price |
|--------|-------|
| Extra operator seat (6+) | **+$1,000 / seat / month** |
| Dedicated VPC teamserver | +$2k–5k/mo |
| On-prem air-gapped | Custom (from $15k/mo) |

### Pilot / design-partner pricing

| Stage | Price / org / mo | Seats | Purpose |
|-------|------------------|-------|---------|
| **Design partner** (first 3 orgs) | **$2,500** | 3 min | Feedback, case study |
| **Pilot** (90 days) | **$3,500** | 3 min | Eval → convert to $5k |
| **Production** | **$5,000** | 3–5 | Standard SKU |

**Annual prepay:** $54k/year (10% off) — easier for procurement than monthly.

**No solo seat sales.** Red teams buy as a unit; simplifies sales and matches how engagements run.

---

## 3. Who buys

### Primary ICP

1. **Internal red teams** — 3–5 operators (perfect fit)
2. **Boutique offensive consultancies** — small team, bill-through to clients
3. **MSSPs** — may need seat overages or custom org tier later

### Buyer persona

| Role | Cares about |
|------|-------------|
| **CISO / Red team lead** | Audit, approvals, team coverage |
| **Lead operator** | Speed, AI chaining, less module trivia |
| **Procurement** | One PO, clear seat cap, MSA |

### Why $5k/mo for the team

- **~$1k–1.7k/seat/mo** vs hiring another senior operator month
- **Governed AI** vs shadow ChatGPT on engagements
- **One invoice** — simpler than per-seat C2 + separate AI tools
- **Pitch:** “Small red team in a box” — 3 people + Erebus ≈ 5-person throughput

---

## 4. Current state (honest scorecard)

| Dimension | Score (1–10) | Gap to $5k/org sale |
|-----------|--------------|---------------------|
| C2 engine | 7 | Deploy story, HA |
| Implant (Go) | 6 | Builder UX, stability |
| AI agent + tools | 5 | Plan/Auto modes, reliability |
| Operator UX (AI TUI) | 6 | Onboarding, no stubs |
| Console REPL | 3 | Hide or wire |
| Enterprise (RBAC, audit) | 1 | Blocker for F500 |
| Demo / narrative | 3 | **Biggest blocker** |
| Billing / MSA | 0 | Required |

**Verdict:** Ready for **design partners** at $2.5k/org. Production **$5k/org** needs Golden Demo + audit + contract.

---

## 5. Product moat

1. **Intent in, actions out** — Objective → agent → implant → structured results → suggestions.
2. **Human-in-the-loop** — High-risk tasks require approval; policy on server.
3. **Engagement memory** — Sessions, loot, history feed the agent.
4. **Suggestion graph** — `next_suggested_actions` on recon output.
5. **Team identity** — Up to 5 named operators, auditable per seat.

**Investor line:** “Intent layer for offensive ops — team-priced, Cobalt-grade execution, compliance built in.”

---

## 6. Roadmap to sellable $5k/org

### Phase 0 — Golden Demo (weeks 1–4)

**Goal:** 5–8 min recorded demo; 5 consecutive live successes.

- Lab (GOAD mini), fixed AD objective, Plan/Auto wired, hide console stubs, sizzle video.

---

### Phase 1 — Pilot SKU (weeks 5–10) · **$2.5–3.5k/org**

- mTLS seat provisioning (3–5 certs)
- Operator audit log
- `make install` + `erebus serve` onboarding doc
- MSA + Authorized Use Policy
- **Exit:** 1 external org runs pilot without founder on call

---

### Phase 2 — Production (weeks 11–20) · **$5k/org**

- RBAC (admin / operator)
- Encrypted config, engagement workspaces
- Report export, Docker/Terraform deploy
- **Exit:** 3 paying orgs @ $5k/mo = **$15k MRR**

---

### Phase 3 — Fundable scale (months 6–12)

| Milestone | Target |
|-----------|--------|
| ARR | $300k–600k (5–10 orgs @ $5k/mo) |
| Customers | 8–12 orgs |
| Case studies | 2 |
| **Seed** | $1.5M–$3M @ $15k+ MRR (3 orgs) |

---

## 7. Go-to-market

1. **Target:** 50 internal red teams + 30 consultancies.
2. **Hook:** “AI completes an AD attack path in 8 minutes — your team of 3, one platform.”
3. **Offer:** Design partner **$2.5k/mo org** (3 seats min, 90 days).
4. **Close:** Convert to **$5k/mo org** at day 60.

**Do not:** per-seat pricing pages, unlimited seats at $5k, or web UI before Golden Demo.

---

## 8. Deck slide — business model

> **$5,000 / month / organization**  
> 3 seats minimum · 5 seats included · AI-native C2 + agent + approvals

**Traction math:** 10 customers = **$50k MRR** = **$600k ARR**

---

## 9. Risks

| Risk | Mitigation |
|------|------------|
| “Too expensive vs CS” | Bundle 5 seats; compare to team cost not single license |
| “Too cheap for MSSP” | Seat overages + enterprise tier |
| Misuse | AUP, customer vetting |
| AI flakiness | Golden path evals, Plan mode, approvals |

---

## 10. Metrics

| Sales | Target |
|-------|--------|
| **Orgs signed** | Primary KPI (not loose seat count) |
| MRR | $5k × orgs (plus overages) |
| Pilot → paid conversion | >50% |
| **Funding trigger** | **$15k MRR** (3 orgs) → seed conversations |

---

## 11. 30 / 60 / 90 days

### 0–30
- [ ] Golden Demo + video
- [ ] Plan/Auto wired
- [ ] MSA + AUP
- [ ] Outbound list (50 orgs)

### 31–60
- [ ] Design partner #1 @ **$2.5k/mo org** (3 seats)
- [ ] Audit log v1
- [ ] Onboarding &lt; 1 hr to callback

### 61–90
- [ ] 3 orgs total → **$15k MRR** (mix of $2.5k pilots + $5k paid)
- [ ] Update deck traction slide

---

## 12. Summary

| Question | Answer |
|----------|--------|
| Price | **$5k/mo per org**, **3 seats min**, **5 seats max** included |
| vs Cobalt Strike | ~3–4× per seat at full bundle — team AI platform, not solo C2 |
| Show-off MVP | **4–8 weeks** |
| First revenue target | **3 orgs = $15k MRR** |
| Seed-ready | **$15k–50k MRR**, 3–10 org logos |

**North star:** A 3-person red team pays **one $5k/mo invoice**, watches autonomous AD ops with approvals, and never sees “coming soon” in the UI.

---

*Last updated: 2026-06-27*