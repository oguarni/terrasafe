# GCP for the first time — your $300 / 90-day playbook

Your "$300 in less than 3 months" is the **Google Cloud Free Trial**: $300 of
credit that expires **90 days** after you activate it. Good news: the
`e2-medium` VM in this setup costs **~$25/mo**, so $300 is *far* more than
you'll burn in 90 days. The real risk isn't running out — it's accidental
charges and forgetting to clean up. This guide handles both.

This is the beginner orientation. The actual deploy commands live in
[DEPLOY_GCP.md](DEPLOY_GCP.md); this page gets you to the point where you can
run them safely.

---

## The mental model (read this once)

GCP nests like this:

```
Billing Account  ($300 credit lives here, tied to your card)
   └─ Project      ("terravault" — a billing + permissions boundary)
        └─ Resources (your VM, static IP, firewall rules…)
```

You delete resources or the whole project to stop spending. The card is only
for identity verification during the trial — **you are not charged
automatically when the trial ends**; you'd have to manually click "Upgrade to
paid." So you can't get a surprise bill from the trial itself.

---

## Step 1 — Activate the free trial

1. Go to <https://console.cloud.google.com/> and sign in with your Google
   account.
2. Click **Activate** / **Start free trial** (top banner). Pick **Brazil** as
   country, accept terms.
3. Enter a credit/debit card (identity check — a small temporary auth hold may
   appear and reverse).
4. You'll land on the Console with **"$300 credit, 90 days remaining"** shown
   in the billing area.

---

## Step 2 — Create a project

1. Top bar → project dropdown → **New Project**.
2. Name it `terravault`. Note the generated **Project ID** (e.g.
   `terravault-472913`) — you'll use it everywhere.

---

## Step 3 — Set a budget alert (do this *before* deploying)

This is your safety net. It won't stop spending, but it emails you.

1. Console → **Billing → Budgets & alerts → Create budget**.
2. Scope: your billing account. Amount: **$50** (well above your ~$25/mo).
3. Alert thresholds: 50%, 90%, 100% → email yourself.

Now if anything misbehaves, you hear about it days before it matters.

---

## Step 4 — Install the CLI and log in

Everything after this is copy-paste from the deploy guide. On Windows, use
**WSL/Ubuntu** or **Cloud Shell** in the browser (easiest for a first run).

```bash
gcloud init                              # log in, pick the terravault project
gcloud auth application-default login
gcloud services enable compute.googleapis.com
```

> 💡 **Easiest path for first-timers:** click the **Cloud Shell** icon (`>_`)
> at the top-right of the Console. It's a free in-browser terminal, already
> authenticated, with `gcloud` ready. No local install needed.

---

## Step 5 — Follow the deploy guide

From here, run [DEPLOY_GCP.md](DEPLOY_GCP.md) top to bottom — steps 1→9. In
order, it has you:

1. Reserve a static IP (step 1)
2. Open the firewall (step 2)
3. Create the VM (step 3) ← *the moment billing starts*
4. Point DuckDNS at the IP (step 4)
5. Install Docker, clone, set secrets, train the model, `docker compose up`
   (steps 5–8)
6. Smoke-test `https://your-domain/health` from your laptop (step 9)

Roughly **30–45 minutes** for a first run.

---

## Budget math (so you can relax)

| Item | Cost | 90-day total |
|---|---|---|
| `e2-medium` VM, 24/7 | ~$25/mo | ~$75 |
| 30 GB disk + static IP (attached) | ~$4/mo | ~$12 |
| **Total** | **~$29/mo** | **~$87 of your $300** |

You'll use less than a third of the credit. To stretch it further, **stop the
VM when you're not demoing it**:

```bash
gcloud compute instances stop terravault-prod --zone=$ZONE
```

That pauses compute charges while keeping your IP and disk.

---

## When the trial ends (~day 90)

Nothing auto-charges. To avoid *any* possibility of a bill, run the
**Teardown** block at the bottom of [DEPLOY_GCP.md](DEPLOY_GCP.md) (deletes VM,
IP, firewall rule). Or just delete the whole project: Console → **IAM & Admin →
Settings → Shut down**.

---

## Honest cautions for a first-timer

- The card hold during signup is normal and reverses — don't panic.
- Billing starts the instant the VM is *created* (step 3), not when you first
  hit it. The DuckDNS/IP/firewall steps before it are free.
- A stopped VM still bills for its **disk + reserved IP** (a few cents/day) —
  fully free only when *deleted*.
