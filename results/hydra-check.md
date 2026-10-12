# HydraDB check (no AI)

- Nothing returned from another role's folders: **57/57** queries
- Kept away from roles that may not read it: **19/19**
- Right file found when the role may read it: **25/25**
- Knowledge graph fully on (thinking mode), restricted answers or hidden document names anywhere in HydraDB's response: **0/13** cases ✅ none · 2 not testable (the answer's words are also in that role's own documents) · 4 with nothing to leak (the answer's document is in no role's folders, so it was never uploaded)

A = may read the answer's folder · N = may not · ✅ right · ❌ wrong

| Question | contractor | support | engineer | hr |
|---|---|---|---|---|
| How do I set up the VPN? | ✅A | ✅A | ✅A | ✅A |
| What is the guest Wi-Fi network called? | ✅A | ✅A | ✅A | ✅A |
| How many vacation days do employees get each year? | ✅A | ✅A | ✅A | ✅A |
| How much does the Team plan cost? | ✅A | ✅A | ✅A | ✅A |
| A customer can't sign in after updating to 3.2. What should they do? | ✅N | ✅A | ✅A | ✅N |
| How do I escalate a ticket to Engineering? | ✅N | ✅A | ✅A | ✅N |
| What's new in release 3.2? | ✅N | ✅A | ✅A | ✅N |
| When does offline mode ship? | ✅N | ✅N | ✅A | ✅N |
| What's the salary range for a senior software engineer? | ✅N | ✅N | ✅N | ✅A |
| When is the employee referral bonus paid? | ✅N | ✅N | ✅N | ✅A |
| What is our 2026 cloud budget? | ✅N | ✅N | ✅N | ✅N |
