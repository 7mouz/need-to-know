# HydraDB search mode: fast vs thinking (no AI)

We reworded 10 questions so they don't use the documents' own words ("paid" instead of "salary") and asked each one as a role allowed to read the answer. The numbers show where the right document ranked among the 6 excerpts `nk hydra-ask` gives the AI (#1 = top).

| Role | Reworded question | Right document | fast | thinking |
|---|---|---|:-:|:-:|
| contractor | How do I reach internal tools when I'm working from home? | it/it-runbook.md | #2 | #2 |
| contractor | What Wi-Fi should visitors use? | handbook/office-handbook.md | #1 | #1 |
| contractor | How much time off do staff get per year? | handbook/holiday-policy.md | #1 | #1 |
| contractor | How much is the Team subscription? | public/product-faq.md | #1 | #1 |
| support | A client keeps getting kicked out at login since the update. What do we tell them? | support/known-issues.md | #2 | #1 |
| support | How do I hand a ticket over to the developers? | support/support-playbook.md | #2 | #1 |
| support | What changed in the latest version? | product-docs/release-notes-v3.2.md | #1 | #1 |
| engineer | When can customers use the app with no internet? | roadmap/product-roadmap.md | #2 | #4 |
| hr | How much do senior engineers get paid? | hr/salary-ranges.md | #3 | #1 |
| hr | When does someone get the reward for recommending a friend who gets hired? | hr/hiring-plan-2026-q4.md | missed | #1 |

| | fast | thinking |
|---|:-:|:-:|
| Right document first | 4 / 10 | **8 / 10** |
| In the top 3 | 9 / 10 | 9 / 10 |
| Found at all | 9 / 10 | **10 / 10** |
| Average search time | 0.3 s | 1.8 s |

`nk hydra-ask` now uses thinking mode. All 20 searches carried the role's access list, and none returned anything from another role's folders.
