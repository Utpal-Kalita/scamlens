/* ScamLens - transparent, rule-based scam-signal analysis, fully in-browser.
   Pasted text is DATA: it is escaped before rendering, never executed,
   and embedded links are shown as text, never fetched or made clickable. */
"use strict";

// Each rule: id, label, why it matters, severity (2 = stronger, 1 = weaker),
// and a regex evaluated against the raw text (case-insensitive).
const RULES = [
  { id: "urgency", label: "Artificial urgency", sev: 2,
    why: "Scammers manufacture time pressure so you act before thinking. Genuine organizations give you time to verify.",
    re: /\b(urgent(?:ly)?|immediat(?:e|ely)|act now|right now|expires? (?:in|within|today)|\d+\s*(?:min(?:ute)?|hrs?|hours?)\s*(?:left|remaining)|last chance|final (?:notice|warning)|today only|offer (?:ends|expires))\b/i },
  { id: "pay2receive", label: "Upfront payment demand", sev: 2,
    why: "Jobs, prizes, loans and deliveries never require a fee to release money that is supposedly already yours.",
    re: /\b(pay|send|deposit|transfer)\b[^.\n]{0,40}\b(fee|charge|verification|processing|refundable|advance|gst|tax|registration)\b|\b(?:fee|charge) of\b|\b(?:rs\.?|inr|₹|\$|usd)\s?\d+[^.\n]{0,30}\b(?:fee|verification|process|release|claim)\b/i },
  { id: "credentials", label: "Asks for codes, PINs or passwords", sev: 2,
    why: "When someone who contacted you first - a message, call or email you did not initiate - asks for an OTP, CVV, PIN or password, treat it as a takeover attempt. Genuine services only ask for codes inside their own app or site, when you started the login.",
    re: /\b(otp|one[- ]time (?:pass)?code|verification code|cvv|card pin|atm pin|password|mpin|upi pin|screen ?share|anydesk|teamviewer)\b/i },
  { id: "impersonate", label: "Authority or brand pressure", sev: 1,
    why: "Scams borrow trusted names - banks, tax offices, police, couriers, CEOs - to stop you questioning the request.",
    re: /\b(rbi|income tax|customs|police|cid|ed office|bank (?:manager|official)|ceo|managing director|hr (?:manager|department)|amazon|flipkart|fedex|dhl|blue ?dart|india post|sbi|hdfc|icici|paytm|irs)\b/i },
  { id: "toogood", label: "Unsolicited reward", sev: 2,
    why: "You cannot win a contest you never entered, and strangers do not hire without interviews at above-market pay.",
    re: /\b(congratulations|you(?:'| ha)ve (?:been )?(?:selected|won|won a)|winner|lottery|prize|lucky draw|cash ?back offer|claim your|free (?:gift|iphone|laptop)|selected for)\b/i },
  { id: "link", label: "Link demanding action", sev: 1,
    why: "Shortened, misspelled or look-alike links lead to fake login and payment pages. This tool shows links as text only - never opens them.",
    re: /\b(?:https?:\/\/|www\.|bit\.ly|tinyurl|t\.co\/|goo\.gl\/|[a-z0-9-]+\.(?:xyz|top|club|icu|buzz|live|link|click|site|online)\b)[^\s]*/i },
  { id: "secrecy", label: "Secrecy or isolation", sev: 2,
    why: "Being told not to tell family, colleagues or the bank is one of the strongest scam signals there is.",
    re: /\b(do(?:es)? not tell|don't tell|keep (?:this|it) (?:a )?(?:secret|confidential)|confidential(?:ly)?|between us|no one (?:else|should))\b/i },
  { id: "threat", label: "Threat of penalty", sev: 2,
    why: "Arrest, account closure and legal action threats exist to panic you into compliance. Real agencies do not operate over DMs.",
    re: /\b(arrest|legal action|police case|account (?:will|would) be (?:blocked|frozen|suspended|closed)|sim (?:will|would) be blocked|kyc (?:expired|pending|update)|suspend(?:ed)? your|block(?:ed)? your account|fine of)\b/i },
  { id: "generic", label: "Generic greeting to an unknown recipient", sev: 1,
    why: "Mass-sent scams avoid your name. A greeting that could fit anyone suggests the sender does not actually know you.",
    re: /^(?:\s*)(dear (?:customer|user|sir|madam|friend|beneficiary)|hello (?:dear|friend)|hi there|dear valued)/i },
  { id: "paymentrail", label: "Hard-to-reverse payment route", sev: 2,
    why: "Gift cards, crypto and wallet transfers are demanded precisely because you cannot claw the money back.",
    re: /\b(gift ?cards?|itunes|google play card|steam card|bitcoin|btc|usdt|crypto(?:currency)?|western union|money ?gram|upi id|wallet transfer)\b/i },
];

const SAMPLES = {
  job: "CONGRATULATIONS! You have been SELECTED for Work From Home Data Entry job, salary 45,000/month, no interview needed. To activate your offer letter, pay refundable registration fee of Rs.499 within 30 MINUTES via UPI id quickhire@okaxis. Offer expires today. Do not tell anyone, limited seats. Contact HR Manager on WhatsApp http://bit.ly/hr-activate-now",
  bank: "Dear Customer, Your SBI account KYC has EXPIRED. Your account will be BLOCKED today and SIM will be deactivated. Update KYC IMMEDIATELY at www.sbi-kyc-update.top/verify. Keep your ATM pin, OTP and card details ready. This is final notice from bank official. - SBI",
  parcel: "INDIA POST: Your parcel is held at customs. Pay Rs.99 clearance fee within 2 hours or package returns to sender and legal action may be initiated. Track & pay: http://indiapost-deliver.xyz/pay?id=88271. Do not ignore this final warning.",
  legit: "Hi Ananya, this is Priya from the design team. Our sprint review moved to Friday 3 pm in the usual Meet room - the calendar invite has the link. No rush, but could you bring the latest mockups? See you there!",
};

const SEV_WORD = { 2: "high", 1: "med" };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Collect matches rule by rule. Overlaps are resolved by first-come order so
// every character is highlighted at most once, with the earlier (stronger)
// rule winning.
function analyze(text) {
  const hits = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.re.source, "gi");
    let m;
    while ((m = re.exec(text)) !== null) {
      hits.push({ start: m.index, end: m.index + m[0].length, rule, text: m[0] });
      if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loops
    }
  }
  hits.sort((a, b) => a.start - b.start || b.rule.sev - a.rule.sev);
  const accepted = [];
  let cursor = -1;
  for (const h of hits) {
    if (h.start >= cursor) { accepted.push(h); cursor = h.end; }
  }
  return accepted;
}

function annotate(text, hits) {
  let out = "", pos = 0;
  for (const h of hits) {
    out += escapeHtml(text.slice(pos, h.start));
    out += `<mark class="${SEV_WORD[h.rule.sev]}" title="${escapeHtml(h.rule.label + ": " + h.rule.why)}">${escapeHtml(h.text)}</mark>`;
    pos = h.end;
  }
  out += escapeHtml(text.slice(pos));
  return out;
}

function render() {
  const text = document.getElementById("msg").value;
  const results = document.getElementById("results");
  if (!text.trim()) { results.hidden = true; return; }
  const hits = analyze(text);
  const strong = hits.filter((h) => h.rule.sev === 2).length;
  const mild = hits.length - strong;

  const summary = document.getElementById("summary");
  const sub = document.getElementById("summarySub");
  if (hits.length === 0) {
    summary.textContent = "No known warning signs found in this text";
    sub.textContent = "That is not proof a message is safe - new scams appear daily. Verify unexpected requests anyway.";
  } else {
    summary.textContent = `${hits.length} potential warning sign${hits.length > 1 ? "s" : ""} found (${strong} stronger, ${mild} weaker)`;
    sub.textContent = "Read each highlighted sign below and decide calmly. Multiple strong signs together deserve real caution.";
  }
  const pct = Math.min(100, Math.round((strong * 22 + mild * 8)));
  document.getElementById("meterFill").style.width = pct + "%";

  document.getElementById("annotatedText").innerHTML = annotate(text, hits);

  const byRule = new Map();
  for (const h of hits) {
    if (!byRule.has(h.rule.id)) byRule.set(h.rule.id, { rule: h.rule, evidence: [] });
    byRule.get(h.rule.id).evidence.push(h.text);
  }
  const flagList = document.getElementById("flagList");
  flagList.innerHTML = "";
  if (byRule.size === 0) {
    flagList.innerHTML = `<div class="flag"><b>Nothing triggered</b><p>No rule matched. Ordinary conversation usually looks like this.</p></div>`;
  }
  [...byRule.values()].sort((a, b) => b.rule.sev - a.rule.sev).forEach(({ rule, evidence }) => {
    const el = document.createElement("div");
    el.className = "flag";
    el.innerHTML = `<span class="sev ${SEV_WORD[rule.sev]}">${rule.sev === 2 ? "stronger" : "weaker"}</span><b>${escapeHtml(rule.label)}</b>
      <p>${escapeHtml(rule.why)}</p>
      <p class="evidence">Found: ${escapeHtml([...new Set(evidence)].slice(0, 3).map((e) => `"${e.length > 60 ? e.slice(0, 60) + "..." : e}"`).join(", "))}</p>`;
    flagList.appendChild(el);
  });
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

document.getElementById("analyze").addEventListener("click", render);
document.querySelectorAll(".sample").forEach((b) =>
  b.addEventListener("click", () => {
    document.getElementById("msg").value = SAMPLES[b.dataset.sample];
    render();
  })
);
