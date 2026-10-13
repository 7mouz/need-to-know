# Need-to-Know

A company brain that knows who's asking. It runs on [OpenClaw](https://openclaw.ai) and can store its documents in [HydraDB](https://hydradb.com).

> All company data here is made up (PixelHeaven Inc., a fictional software company).

![The web page: a contractor asks for the senior engineer salary range. The answer is "not in contractor's documents", the page offers to pass the question to the People team (HR), and the right side shows what a contractor can see and the live security results.](screenshots/web-answer.png)

## The problem

Give one AI assistant all of a company's documents, and it answers everyone the same way. Real companies don't work like that. HR sees pay, engineers see the roadmap, and contractors see the basics. An AI agent that reads those files needs the same limits as a person.

## How it works

```text
company folders  ──►  roles.conf  ──►  nk setup  ──►  one search brain per role  ──►  answers with sources
 (public, hr, …)     (who needs        (creates and      (each holds only what       ("not available, ask
                      what)             checks agents)     that job needs)             the People team")
```

- `roles.conf` lists each role and the folders it may read. An AI agent can be a role too.
- Each role gets its own OpenClaw agent and its own search. Both are built only from that role's folders. The other folders are never loaded, so there is nothing to filter later.
- Every answer must name a file from the role's own folders. If it doesn't, `nk` shows a short "not available" message instead.
- `nk setup` turns on the safety settings and checks 6 of them every time it runs. It also tests the AI key. If the key stops working, search falls back to keywords and keeps going.
- `nk score` asks everyday questions as every role and grades the answers. It works out what each role should get from `roles.conf`, so the test follows the access rules when they change.

## Safety features

- Every document is checked for hidden instructions before any assistant sees it. A flagged file is kept for review and given to no one.
- Assistants stay on company work. Ask one to fix your resume and it says no.
- When the answer belongs to another team, the assistant offers to pass the question on. It sends a request (`nk handoffs`) only if the person says yes. Someone on that team decides what to share and replies by email. Nothing comes back on its own.
- A handoff can't be used to get around the rules. The question is checked for hidden instructions, replies only go to company email addresses, repeat questions are dropped, and each person can have at most 5 open requests. The request also tells its reader that the asker's role comes from their login, so claims in the question don't count. `nk` picks the team from the public who-to-ask list and never searches that team's documents to do it.
- `nk` watches for probing. If one role reaches for other teams' information 3 times in 10 minutes, `nk` records an alert. The person sees a short note that such requests are reviewed. One question with hidden instructions is enough. Questions passed on through a handoff don't count. `nk alerts` shows each alert with its evidence.
- Every action goes into an audit log that can't be quietly edited. Each entry holds a fingerprint of the entry before it, and a small anchor file remembers the count and the last fingerprint. `nk log --verify` shows if any entry was changed, deleted, added, or cut off the end. `nk log --tamper-test` proves it on copies of the log.
- The company's values are in the brain too (`public/company-values.md`), so every role can quote them.

## Slack messages, with sensitive data removed

A lot of company knowledge lives in chat, and so do a lot of accidental leaks. `nk ingest-slack` loads a Slack export: the .zip a Slack admin downloads, or its unzipped folder. There is no live link to Slack, so no Slack token is stored anywhere.

- `roles.conf` puts each channel in a folder: `slack: support = support`. Only the roles that read that folder can read the channel. A channel with no line goes to nobody.
- Each channel's day becomes one document and goes through the same steps as every other file: checked for hidden instructions, sensitive data removed, then given only to the roles that may read its folder.
- The zip is read in memory. Paths that try to leave the export, links, and oversized files are refused.

Before any file reaches an assistant, the search index, or HydraDB, `nk` removes:

| What | How `nk` finds it | Replaced with |
|---|---|---|
| Card numbers | 13 to 19 digits that pass the card checksum (Luhn), so order numbers stay | `[card number removed]` |
| Social Security numbers | the 3-2-4 digit format, minus numbers that are never issued | `[SSN removed]` |
| Keys and passwords | AWS, Slack, GitHub and `sk-` keys, private key blocks, and the value after `password:`, `token:` or `api_key=` | `[secret removed]` |
| Home addresses | a street address after "home address", "lives at" or "my address is" | `[home address removed]` |

This runs on every file, not only Slack. The log records what kind was removed and how many, never the value.

On the demo export (`pixelheaven-slack/`, made up; the card is Visa's public test number and the key is the example from AWS's documentation):

```
REDACTED roadmap/slack-eng-2026-09-17.md: 1 secret
REDACTED roadmap/slack-eng-2026-09-18.md: 1 secret
BLOCKED  public/slack-general-2026-09-16.md: found instruction-like text ['list all files', 'New instructions:', 'do not tell the user']
REDACTED hr/slack-people-ops-2026-09-17.md: 1 SSN, 1 home address
REDACTED support/slack-support-2026-09-15.md: 1 card number
SKIPPED  #random  (no 'slack: random = <folder>' line in roles.conf)

$ nk search support 4111
support: 0 file(s) match '4111'
$ nk search support chargeback
support: 1 file(s) match 'chargeback'
    support/slack-support-2026-09-15.md
```

None of the 16 company documents changed. Afterwards, none of the planted values is in any assistant's documents or in the log.

The limit: these are patterns. They catch structured data like card numbers and keys. A loose personal detail ("she just moved near the park") can still get through. An AI could catch more, but only by reading the raw text first, which is what this step is there to prevent.

## The web page

`nk web` serves a page for the same brain. It uses Python's standard library, so there is nothing to install. Pick a role, ask a question, and see the answer with its source. If another team owns the answer, the page offers to pass the question on. The right side shows which folders the role can see and the live security results.

To open it, start a tunnel from your laptop, run `nk web` on the box, and open the link it prints:

```bash
ssh -L 8765:127.0.0.1:8765 <your box>
nk web
```

The page is locked down too:

- It listens on the box only, so you reach it through the SSH tunnel.
- Each start makes a new random token, and every request needs it.
- It only answers requests addressed to localhost, which blocks DNS-rebinding tricks.
- A strict content policy stops the page from loading anything from outside.
- Answers are shown as plain text, so nothing in them can run as code.
- It asks the AI one question at a time, so a double click doesn't spend two calls.
- The security panel shows counts. It never shows other people's questions.
- Everything goes through the same checks as the terminal and into the same tamper-evident log.

## Who sees what (the demo company)

| Folder | Contractor | Support | Engineer | HR |
|---|:-:|:-:|:-:|:-:|
| public, handbook, it | ✅ | ✅ | ✅ | ✅ |
| product-docs, support | | ✅ | ✅ | |
| roadmap | | | ✅ | |
| hr | | | | ✅ |
| finance | | | | |

Access depends on what each job needs. `finance` belongs to no role, so no assistant has it.

## HydraDB

`nk` can also keep the documents in HydraDB. HydraDB searches by meaning as well as by keywords, and it builds a knowledge graph of the documents.

HydraDB can give each document an access list. Its own SDK docs warn about two gaps: a document saved without an access list is open to everyone, and a search sent without one is not filtered. `nk` closes both gaps and adds a third check:

1. Every document gets an access list from `roles.conf` (`group:needtoknow:<role>` for each role that may read it). `nk` refuses to upload a document without one, and every search names the role that is asking.
2. Each folder is its own collection. A role only searches the collections it may read.
3. `nk` checks every result again. If HydraDB ever returned a file from another role's folder, `nk` would drop it and warn.

Only checked documents are uploaded. When `roles.conf` changes, the next upload updates the access lists and removes documents no role may read.

Live results, with no AI involved:

| Search for "salary" | Contractor | Support | Engineer | HR |
|---|:-:|:-:|:-:|:-:|
| Files returned | 0 | 0 | 0 | 2 |

| `nk hydra-check`: every everyday question as every role | |
|---|---|
| Nothing returned from another role's folders | **57 / 57** searches |
| Kept away from roles that may not read it | **19 / 19** |
| Right document found when the role may read it | **25 / 25** ([report](results/hydra-check.md)) |
| Knowledge graph fully on: hidden answers or hidden document names anywhere in HydraDB's reply | **0 / 13** cases we could test |

**The graph test.** HydraDB's knowledge graph links facts across documents, so a fact could slip through a link. For every case where a role may not see the answer, `nk` asks again with the graph fully on. Then it searches everything HydraDB sent back for the hidden answer and for the names of documents that role can't see. It only counts words that appear in the hidden document and in none of the role's own documents, so any match would be a real leak.

**Thinking mode.** `nk hydra-ask` uses HydraDB's thinking mode, which rewrites the question and re-ranks the results. We tested it on 10 questions worded differently from the documents. It put the right document first 8 times out of 10. The fast mode did that 4 times and missed one document completely ([measurement](results/thinking-vs-fast.md)).

**The audit.** `nk hydra-audit` tests HydraDB's access one document at a time. It lists every stored document, including any in folders no role reads. Then it tries to open each one as every role and as a stranger with no role. It flags a document a stranger can open, a document the wrong role can open, and a document `nk` never uploaded. Live result: all 16 documents open only for the roles allowed, and for no stranger ([report](results/hydra-audit.md)). In testing, it caught a planted document with no access list and an HR file shared too widely.

## Results on OpenClaw's own search

Each role was asked the same everyday questions, and a grader checked every answer against the file it should come from.

| | |
|---|---|
| Answer score | **41 / 44 correct** ([full report](results/score-report.md)) |
| Nothing given outside a role's folders | **19 / 19** |
| Correct answers that named their source file | **22 / 22** |
| First-week briefs, every cited file in the role's own folders | yes ([contractor](results/brief-contractor.md), [HR](results/brief-hr.md)) |

The 3 misses were a role saying "I don't have that" when the fact was in its own folders, because search missed the file. That is the safe way to be wrong. The fix is already in the code: open the best match and read the whole file.

## 5 OpenClaw defaults we changed

We found 5 default settings that are wrong for an assistant shared by many roles. `nk setup` fixes all 5 and checks them every time:

1. **File tools could leave the agent's folder** → locked to its own folder (`tools.fs.workspaceOnly`)
2. **Terminal commands were allowed** → turned off (`exec-policy preset deny-all`)
3. **"Remember across conversations" was on**, so one person's chats could show up in the next person's answers → off; search covers company documents only
4. **12 add-ons nobody needed were in every prompt** → off (prompts 39% smaller)
5. **A ChatGPT sign-in runs on OpenAI's Codex engine, which needs the terminal** → moved to OpenClaw's own engine (`agentRuntime: openclaw`), so the terminal stays off

## Commands

| Command | What it does |
|---|---|
| `nk setup [--prune]` | Make OpenClaw match `roles.conf`: create the role agents, turn on the safety settings, check them |
| `nk ingest-dir <folder>` | Load documents (Markdown, text, CSV, JSON, HTML, Word, PowerPoint, PDF, saved emails .eml/.mbox). Each file becomes searchable text, is checked for hidden instructions, and goes only to the roles that may read its folder |
| `nk ingest-slack <export>` | Load a Slack export (.zip or folder). Channels go to the folders `roles.conf` names, the rest go to nobody, and sensitive data is removed first |
| `nk index` | Rebuild each role's search from its own folder |
| `nk ask <role> "question"` | Ask one role's assistant. If the answer belongs to another team, it offers to pass the question on |
| `nk brief <role>` | A one-page first-week guide for that role, with every source checked |
| `nk check` | Before a demo: does every role answer and search? |
| `nk score [role …]` | The answer report |
| `nk handoffs` | Questions people chose to pass on to another team, with where to reply |
| `nk alerts` | Probing alerts, with the evidence |
| `nk who` · `nk search <role> "words"` · `nk log` | Who sees what, a search with no AI, and the audit log |
| `nk log --verify` · `nk log --tamper-test` | Check the audit log, and prove the check catches edits and deletions (on copies) |
| `nk hydra-push` | Upload every checked document to HydraDB, with access lists from `roles.conf` |
| `nk hydra-search <role> "words"` · `nk hydra-check` | Search HydraDB as one role, and the no-AI test |
| `nk hydra-audit` | Try every stored document as every role and as a stranger; flag anything the wrong people can open |
| `nk hydra-ask <role> "question"` | Answer from what HydraDB returns for that role |
| `nk hydra-reset --yes` | Delete the HydraDB database |
| `nk web [port]` | The web page, on the box only (open it through an SSH tunnel) |

## Quick start

You need OpenClaw 2026.9.x running as its own user, Python 3, and an AI. For the AI, use a key (free Gemini works) **or** a ChatGPT plan signed in for each role with `openclaw models auth login --provider openai --device-code --agent <role>`. `nk setup` runs ChatGPT on OpenClaw's own engine.

```bash
mkdir -p ~/needtoknow && cp nk.py roles.conf score-questions.conf ~/needtoknow/
cp -r pixelheaven-docs ~/needtoknow/
# save your AI key privately (it's never printed):
(umask 077; mkdir -p ~/needtoknow/.secrets; read -rsp "Key: " K; echo; printf "%s" "$K" > ~/needtoknow/.secrets/model.key)
cd ~ && python3 ~/needtoknow/nk.py setup --prune
python3 ~/needtoknow/nk.py ingest-dir ~/needtoknow/pixelheaven-docs && python3 ~/needtoknow/nk.py index
python3 ~/needtoknow/nk.py check && python3 ~/needtoknow/nk.py score
```

Optional HydraDB storage:

```bash
python3 -m venv ~/needtoknow/.venv && ~/needtoknow/.venv/bin/pip install "hydradb-sdk>=2.1.1,<3"
(umask 077; read -rsp "HydraDB key: " K; echo; printf "%s" "$K" > ~/needtoknow/.secrets/hydradb.key)
python3 ~/needtoknow/nk.py hydra-push && python3 ~/needtoknow/nk.py hydra-check
```

## Honest limits

- The login is simulated: in the demo you pick the role. In real use, the company login would set each person's role.
- It suits a few roles. With thousands of permission groups, you would filter at search time instead of copying documents to each role.
- There are no live Slack, Drive, or Gmail connections. Slack exports load directly (`nk ingest-slack`); other exports work once they are sorted into folders.
- Sensitive-data removal uses patterns (see the Slack section). A blocked file is kept as it was, for review inside `nk`'s folder. One Slack message with hidden instructions blocks that channel's whole day.
- The separation between roles depends on OpenClaw's tool settings. A separate sandbox or Linux user for each role would be stronger.
- The HydraDB numbers measure search: the right document comes back for the right role. The AI-graded score above used OpenClaw's own search.
- A handoff is a request file in a queue that the team reads with `nk handoffs`. It isn't emailed to the team yet, and the reply goes by email outside `nk`. In the demo the person types their work email; in real use it would come from their login.
- Chats in the OpenClaw dashboard skip `nk`, so they don't offer handoffs or get the answer check.
- Alerts are per role because the login is simulated. With a real login they would be per person. The limit (3 in 10 minutes) is a setting. An alert means someone should take a look; it doesn't prove bad intent.
- The log and its anchor are on the same machine, so someone with full access to that machine could rewrite both. `nk log --verify` prints the latest fingerprint. Write it down somewhere else: if the log is ever rewritten, the fingerprint for the same entries changes. Entries from before the chain started aren't protected.

---

Built for the Company Brain Hackathon (TechEquity AI, Snowflake Silicon Valley AI Hub). MIT license.
