# ScamLens

Paste a suspicious message. See exactly what to question.

ScamLens is an offline scam-awareness tool. Paste a text message, DM, or email and it highlights potential warning signs - artificial urgency, upfront payment demands, requests for codes or PINs, impersonation, threats, suspicious links - and explains why each one matters, quoting the exact words that triggered it.

**Warning signs, not verdicts.** ScamLens cannot confirm any message is safe or fraudulent. It never tells you a message is "safe" - it shows you what to question and how to verify independently.

## Run it

Fully static site. Open `index.html` or serve the folder:

```
python3 -m http.server 8000
```

Deployed version: (GitHub Pages link added at submission)

## Responsible design

- Analysis is 100% local: a transparent, rule-based pattern library. Nothing is uploaded, stored, or sent anywhere.
- Pasted text is treated as data only: it is HTML-escaped before display, never executed, and links inside it are rendered as plain text - never fetched or made clickable.
- Every flag shows its evidence and reasoning; there are no opaque scores.
- The checklist teaches verification habits (pause, verify independently, never pay to receive, guard codes, ask someone you trust) instead of promising detection.

## Built with

Vanilla HTML/CSS/JavaScript. No dependencies.

Built during SafeSpace Hacks (Oct 17 - Nov 22, 2026). AI assistance used for ideation. Sample messages are synthetic.
