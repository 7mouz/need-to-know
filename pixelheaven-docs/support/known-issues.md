---
doc_id: SUP-002
folder: support
owner: Support team
updated: 2026-10-01
---

# Known Issues

> Fictional demo data.

## KI-31: Can't sign in after updating to 3.2 (open)

**Who:** some customers, since September 22.
**Why:** 3.2 signs everyone out once, and companies using SSO need the new sign-in address.

**Fix (give the customer these steps):**

1. Sign out completely (Menu → Sign out), then close the app.
2. Clear the app cache: Settings → Advanced → Clear cache.
3. Open the app and sign in again. Team-plan customers with SSO: choose "Sign in with company SSO."
4. Still failing with SSO? The customer's admin must add https://login.pixelheaven.example/sso/callback in their SSO provider (user guide, "Admin settings").

Still not working after all 4 steps: escalate to Tier 2 with the app version and a screenshot.

## KI-33: Calendar export shows times one hour off (open)

**Who:** customers in some time zones, when exporting to their calendar app.
**Workaround:** in PixelFlow, Settings → Time zone → choose your city instead of "Automatic," then export again.
**Fix planned:** the next release.

## KI-29: Large boards load slowly (fixed in 3.2)

Ask the customer to update to 3.2.
