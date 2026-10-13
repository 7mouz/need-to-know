# PixelHeaven Inc.: Demo Company Knowledge

**All fictional.** PixelHeaven Inc. is an invented company for the Need-to-Know demo (Company Brain Hackathon). Names, numbers, and customers are made up.

PixelHeaven makes **PixelFlow**, a project-management app.

## Who needs what (the access map)

Access follows what each job needs.

| Folder | What's inside | Contractor | Support | Engineer | HR | Ask if you can't see it |
|---|---|:-:|:-:|:-:|:-:|---|
| `public` | Company overview, product FAQ | ✅ | ✅ | ✅ | ✅ | Marketing team |
| `handbook` | Office handbook, time off, all-hands notes | ✅ | ✅ | ✅ | ✅ | Operations team |
| `it` | IT runbook: VPN, laptops, tool access | ✅ | ✅ | ✅ | ✅ | IT helpdesk |
| `product-docs` | User guide, release notes 3.2 | | ✅ | ✅ | | Product team |
| `support` | Support playbook, known issues, customer tickets | | ✅ | ✅ | | Support team |
| `roadmap` | Product roadmap, planning meeting notes | | | ✅ | | Product team |
| `hr` | Salary ranges, hiring plan | | | | ✅ | People team (HR) |
| `finance` | Vendor list, cloud budget | | | | | Finance team |

No role reads `finance`, so it isn't loaded into any assistant. A folder no role reads stays closed.

## Facts that connect across sources

| Topic | Where it shows up |
|---|---|
| Offline mode | All-hands notes (a hint, no date) · ticket #4520 (customer request) · planning meeting (decision, owner) · roadmap (date) |
| Sign-in trouble after 3.2 | Release notes (the change) · known issues KI-31 (fix steps) · playbook (escalation) · ticket #4512 (customer report) |
| VPN | Office handbook ("see the IT runbook") · IT runbook (steps) |

## Demo questions

| Question | Who gets an answer |
|---|---|
| How do I set up the VPN? | Everyone |
| A customer can't log in after the update. What do I do? | Support, Engineer |
| When does offline mode ship? | Engineer |
| What's the salary range for a senior engineer? | HR |
| How much do we spend with our cloud vendor? | Nobody |
