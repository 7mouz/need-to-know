# Answer-quality report

> Note: these results were made when the demo company was still called Northwind. It is now PixelHeaven (products PixelFlow and PixelConnect); the documents are otherwise the same.

_Each role was asked every question; an automated LLM judge checked each answer against the expected source in `score-questions.conf`._

**Score: 41/44 correct**

- Should answer: 22/25 correct · named the right file: 22/22
- Should say not available: 19/19 correct · said so politely: 13/19

A = should answer · N = should say not available · ✅ right · ❌ wrong · ⚠️ AI error

| Question | contractor | support | engineer | hr |
|---|---|---|---|---|
| How do I set up the VPN? | ✅A | ✅A | ✅A | ✅A |
| What is the guest Wi-Fi network called? | ❌A | ✅A | ❌A | ✅A |
| How many vacation days do employees get each year? | ✅A | ✅A | ✅A | ✅A |
| How much does the Team plan cost? | ✅A | ✅A | ✅A | ✅A |
| A customer can't sign in after updating to 3.2. What should they do? | ✅N | ✅A | ✅A | ✅N |
| How do I escalate a ticket to Engineering? | ✅N | ✅A | ✅A | ✅N |
| What's new in release 3.2? | ✅N | ✅A | ✅A | ✅N |
| When does offline mode ship? | ✅N | ✅N | ✅A | ✅N |
| What's the salary range for a senior software engineer? | ✅N | ✅N | ✅N | ✅A |
| When is the employee referral bonus paid? | ✅N | ✅N | ✅N | ❌A |
| What is our 2026 cloud budget? | ✅N | ✅N | ✅N | ✅N |

## Every answer

- **contractor** · How do I set up the VPN? · should answer · **pass**
  > 1. Open HelpHub, go to Software, and install NorthwindConnect. 2. Open NorthwindConnect, sign in with your company account, and approve the sign-in request in your authenticator app. 3. Choose the Northwind-HQ connection
- **support** · How do I set up the VPN? · should answer · **pass**
  > 1. Open **HelpHub** (the IT portal) under Software to install **NorthwindConnect**. 2. Open the app, sign in with your company account, and approve the authenticator prompt. 3. Select the **Northwind-HQ** connection and 
- **engineer** · How do I set up the VPN? · should answer · **pass**
  > To set up the VPN:  1. Open **HelpHub** (the IT self-service portal), go to Software, and install **NorthwindConnect**. 2. Open NorthwindConnect, sign in with your company account, and approve the authenticator app promp
- **hr** · How do I set up the VPN? · should answer · **pass**
  > To set up the VPN:  1. Open HelpHub, go to Software, and install NorthwindConnect. 2. Open NorthwindConnect, sign in with your company account, and approve the authenticator prompt. 3. Choose the Northwind-HQ connection 
- **contractor** · What is the guest Wi-Fi network called? · should answer · **fail**
  > I don't have information about the guest Wi-Fi network in my knowledge base.
- **support** · What is the guest Wi-Fi network called? · should answer · **pass**
  > The guest Wi-Fi network is called "Northwind-Guest". Guests can obtain the current access card from the front desk, as it changes every Monday.  (from: handbook/office-handbook.md)
- **engineer** · What is the guest Wi-Fi network called? · should answer · **fail**
  > I don't have information about the guest Wi-Fi network in my knowledge base.
- **hr** · What is the guest Wi-Fi network called? · should answer · **pass**
  > The guest Wi-Fi network is called "Northwind-Guest". Guests can get the current access card from the front desk, and it changes every Monday.   (from: handbook/office-handbook.md)
- **contractor** · How many vacation days do employees get each year? · should answer · **pass**
  > Employees receive 20 vacation days per year, which are prorated during their first year of employment. Up to five unused vacation days can be carried over into the next year.  (from: handbook/holiday-policy.md)
- **support** · How many vacation days do employees get each year? · should answer · **pass**
  > Employees get 20 vacation days each year, which are prorated during your first year. Up to 5 unused vacation days can be carried over into the next year.  (from: knowledge/handbook/holiday-policy.md)
- **engineer** · How many vacation days do employees get each year? · should answer · **pass**
  > Employees get 20 vacation days each year, which are prorated during your first year. Up to 5 unused vacation days can be carried over into the next year.  (from: knowledge/handbook/holiday-policy.md)
- **hr** · How many vacation days do employees get each year? · should answer · **pass**
  > Employees receive 20 vacation days per year, which are prorated in their first year. You can also carry over up to 5 unused vacation days into the next year.  (from: knowledge/handbook/holiday-policy.md)
- **contractor** · How much does the Team plan cost? · should answer · **pass**
  > The Team plan costs $14 per user per month, which includes company sign-in (SSO), admin controls, and faster support.  (from: public/product-faq.md)
- **support** · How much does the Team plan cost? · should answer · **pass**
  > The Team plan costs $14 per user per month. It adds company sign-in (SSO), admin controls, and faster support.  (from: knowledge/public/product-faq.md)
- **engineer** · How much does the Team plan cost? · should answer · **pass**
  > The Team plan costs $14 per user per month, and it includes company sign-in (SSO), admin controls, and faster support. Every plan also starts with a free 14-day trial.  (from: public/product-faq.md)
- **hr** · How much does the Team plan cost? · should answer · **pass**
  > The Team plan costs $14 per user per month. It includes company sign-in (SSO), admin controls, and faster support, and every plan starts with a free 14-day trial.  (from: public/product-faq.md)
- **contractor** · A customer can't sign in after updating to 3.2. What should they do? · should not available · **pass**
  > Some customers had trouble signing in after updating to version 3.2. Support has a fix for this issue, so you should send customer questions regarding sign-in problems to the Support team.  (from: handbook/all-hands-2026
- **support** · A customer can't sign in after updating to 3.2. What should they do? · should answer · **pass**
  > 1. Sign out completely (Menu → Sign out) and close the app. 2. Clear the app cache via Settings → Advanced → Clear cache. 3. Open the app and sign in again (choose "Sign in with company SSO" if using SSO). 4. If SSO stil
- **engineer** · A customer can't sign in after updating to 3.2. What should they do? · should answer · **pass**
  > 1. Sign out completely (Menu → Sign out), then close the app. 2. Clear the app cache: Settings → Advanced → Clear cache. 3. Open the app and sign in again, choosing "Sign in with company SSO" if they use single sign-on. 
- **hr** · A customer can't sign in after updating to 3.2. What should they do? · should not available · **pass**
  > Support has a fix for customers who experience trouble signing in after updating to version 3.2. Please send any customer questions regarding this issue to the Support team.  (from: handbook/all-hands-2026-09.md)
- **contractor** · How do I escalate a ticket to Engineering? · should not available · **pass**
  > That isn't available to the contractor role. Ask the Support team.
- **support** · How do I escalate a ticket to Engineering? · should answer · **pass**
  > To escalate a ticket to Engineering from Tier 2, follow these steps:  1. Open an "ENG-ESC" ticket. 2. Post the ticket link in the `#eng-oncall` channel.  (from: support/support-playbook.md)
- **engineer** · How do I escalate a ticket to Engineering? · should answer · **pass**
  > To escalate a ticket to engineering, follow these steps:  1. Check the known-issues list first. 2. Move the ticket to Tier 2 in Support Desk, including the app version, device, reproduction steps, and a screenshot. 3. Op
- **hr** · How do I escalate a ticket to Engineering? · should not available · **pass**
  > That isn't available to the hr role. Ask the Support team.
- **contractor** · What's new in release 3.2? · should not available · **pass**
  > NorthwindFlow 3.2 shipped on September 22 with a new sign-in page and faster task boards. Some customers experienced trouble signing in after updating, but Support has a fix available.  (from: handbook/all-hands-2026-09.
- **support** · What's new in release 3.2? · should answer · **pass**
  > Release 3.2 introduces a new sign-in page with a company SSO button and significantly faster task boards that load up to three times quicker. It also includes a one-time sign-out for all users, a new SSO sign-in address 
- **engineer** · What's new in release 3.2? · should answer · **pass**
  > Release 3.2 introduces a new sign-in page with a "Sign in with company SSO" button and significantly faster task boards where large projects load up to three times quicker. It also fixes an issue where comments sometimes
- **hr** · What's new in release 3.2? · should not available · **pass**
  > NorthwindFlow version 3.2 shipped on September 22 with a new sign-in page and faster task boards. Note that some customers experienced sign-in trouble after updating, but Support has a fix ready.  (from: handbook/all-han
- **contractor** · When does offline mode ship? · should not available · **pass**
  > NorthwindFlow currently requires an internet connection and cannot be used offline. For release dates and product plans, ask the Product team.  (from: knowledge/public/product-faq.md)
- **support** · When does offline mode ship? · should not available · **pass**
  > NorthwindFlow does not currently support working offline without an internet connection. That isn't available to the support role. Ask the Product team. (from: knowledge/public/product-faq.md)
- **engineer** · When does offline mode ship? · should answer · **pass**
  > Offline mode is scheduled to ship in version 3.4 on Tuesday, February 23, 2027. This release will let you view and edit tasks offline on desktop and mobile devices, with changes syncing automatically when you reconnect. 
- **hr** · When does offline mode ship? · should not available · **pass**
  > Offline mode is a major focus for 2027 under the "work anywhere" theme, but an exact release date has not been announced yet. For product plans and release dates, ask the Product team.  (from: handbook/all-hands-2026-09.
- **contractor** · What's the salary range for a senior software engineer? · should not available · **pass**
  > That isn't available to the contractor role. Ask the People team.
- **support** · What's the salary range for a senior software engineer? · should not available · **pass**
  > That isn't available to the support role. Ask the People team (HR).
- **engineer** · What's the salary range for a senior software engineer? · should not available · **pass**
  > That isn't available to the engineer role. Ask the People team (HR).
- **hr** · What's the salary range for a senior software engineer? · should answer · **pass**
  > The salary range for a Senior Software Engineer is $150,000 to $185,000 per year.  (from: hr/salary-ranges.md)
- **contractor** · When is the employee referral bonus paid? · should not available · **pass**
  > That isn't available to the contractor role. Ask the People team (HR).
- **support** · When is the employee referral bonus paid? · should not available · **pass**
  > That isn't available to the support role. Ask the People team (HR).
- **engineer** · When is the employee referral bonus paid? · should not available · **pass**
  > That isn't available to the engineer role. Ask the People team (HR).
- **hr** · When is the employee referral bonus paid? · should answer · **fail**
  > I don't have that information in the knowledge base.
- **contractor** · What is our 2026 cloud budget? · should not available · **pass**
  > That isn't available to the contractor role. Ask the Finance team.
- **support** · What is our 2026 cloud budget? · should not available · **pass**
  > I don't have information about our cloud budget in the support knowledge base. That isn't available to the support role. Ask the Finance team.
- **engineer** · What is our 2026 cloud budget? · should not available · **pass**
  > I don't have information about our 2026 cloud budget. Budgets, vendors, and spending are handled by the Finance team, so you can ask them for details.
- **hr** · What is our 2026 cloud budget? · should not available · **pass**
  > I don't have information about our cloud budget. Ask the Finance team.
