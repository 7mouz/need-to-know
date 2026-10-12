# Need-to-Know

A company brain that knows who's asking. Built on [OpenClaw](https://openclaw.ai).

> All company data here is fictional (Northwind Inc., a made-up software company).

## The problem

A shared AI assistant pointed at all of a company's documents answers everyone the same, no matter who is asking. Real workplaces don't work like that. HR sees pay, engineers see the roadmap, contractors see the basics. An AI agent reading those same files needs the same limits a person would have.

## How it works

```text
company folders  ──►  roles.conf  ──►  nk setup  ──►  one search brain per role  ──►  answers with sources
 (public, hr, …)     (who needs        (creates and      (each holds only what       ("not available, ask
                      what)             checks agents)     that job needs)             the People team")
```

- `roles.conf` lists each role and the folders it reads. A person or an AI agent is one more role.
- Each role gets its own OpenClaw agent and its own search index, built only from its folders. Nothing is filtered at query time, because the other folders were never loaded.
- `nk setup` applies the safety settings and re-checks 5 of them on every run. It also tests the AI key; a dead key drops search to keywords rather than failing.
- A rule keeps each assistant on company work, and `nk` refuses any answer that cites none of the role's own documents. Ask it to fix your resume and you get a refusal, not help. The company name is one line in `roles.conf`.
- `nk score` asks everyday questions as every role and grades the answers. The expected answers come from `roles.conf`, so the tests follow the access rules whenever they change.

## Who sees what (the demo company)

| Folder | Contractor | Support | Engineer | HR |
|---|:-:|:-:|:-:|:-:|
| public, handbook, it | ✅ | ✅ | ✅ | ✅ |
| product-docs, support | | ✅ | ✅ | |
| roadmap | | | ✅ | |
| hr | | | | ✅ |
| finance | | | | |

Access tracks what a job needs rather than seniority. `finance` belongs to no role, so no brain contains it.

## Results

Each role was asked the same everyday questions, and an automated grader checked every answer against its expected source.

| | |
|---|---|
| Answer-quality score | **41 / 44 correct** ([full report](results/score-report.md)) |
| Nothing given outside a role's folders | **19 / 19** |
| Correct answers that named their source file | **22 / 22** |
| First-week briefs, every cited file in the role's own folder | yes ([contractor](results/brief-contractor.md), [HR](results/brief-hr.md)) |

The 3 misses were a role answering "I don't have that" about a fact sitting in its own folders, because search missed the file. That fails safe. The fix is already in the code: open the top match and read its full text.

## 5 OpenClaw defaults we changed

We hit 5 defaults that are wrong for a shared, multi-role brain. `nk setup` fixes and checks all of them on every run:

1. **File tools could leave the agent's folder** → locked to its own folder (`tools.fs.workspaceOnly`)
2. **Terminal commands were allowed** → denied (`exec-policy preset deny-all`)
3. **"Remember across conversations" was on**, so one person's chats could surface in the next person's answers → off; search covers company documents only
4. **12 unneeded add-ons sat in every prompt** → off (prompts 39% smaller)
5. **A ChatGPT sign-in runs on OpenAI's Codex engine, which needs the terminal on** → switched to OpenClaw's own engine (`agentRuntime: openclaw`), so the terminal stays off

## Commands

| Command | What it does |
|---|---|
| `nk setup [--prune]` | Make OpenClaw match `roles.conf`: create role agents, apply and check the settings |
| `nk ingest-dir <folder>` | Load documents (Markdown, text, CSV, JSON, HTML, Word, PowerPoint, PDF, saved emails .eml/.mbox): each file is turned into searchable text, screened, and given only to the roles that may read its top-level folder. Files with hidden instructions are blocked |
| `nk index` | Rebuild each role's search index from its own folder |
| `nk ask <role> "question"` | Ask one role's brain; logged |
| `nk brief <role>` | A one-page first-week brief for that role, with an automatic source check |
| `nk check` | Before a demo: does every role answer and search? |
| `nk score [role …]` | The answer-quality report |
| `nk who` · `nk search <role> "words"` · `nk log` | Who sees what, a search with no AI, and the audit log |

## Quick start

Needs OpenClaw 2026.9.x running as its own user, Python 3, and an AI: a key (free Gemini works) **or** a ChatGPT plan signed in per role (`openclaw models auth login --provider openai --device-code --agent <role>`; `nk setup` runs it on OpenClaw's own engine).

```bash
mkdir -p ~/needtoknow && cp nk.py roles.conf score-questions.conf ~/needtoknow/
cp -r northwind-docs ~/needtoknow/
# save your AI key privately (it's never printed):
(umask 077; mkdir -p ~/needtoknow/.secrets; read -rsp "Key: " K; echo; printf "%s" "$K" > ~/needtoknow/.secrets/model.key)
cd ~ && python3 ~/needtoknow/nk.py setup --prune
python3 ~/needtoknow/nk.py ingest-dir ~/needtoknow/northwind-docs && python3 ~/needtoknow/nk.py index
python3 ~/needtoknow/nk.py check && python3 ~/needtoknow/nk.py score
```

## Honest limits

- The login is simulated. In the demo you pick the role; in real use the company's single sign-on maps each person to a role.
- It suits a handful of roles. For thousands of permission groups you would filter at search time instead of copying documents per role.
- Documents only, with no live Slack, Drive, or Gmail connectors yet. Any export works once it is sorted into folders.
- The isolation rests on OpenClaw's tool settings. A separate sandbox or a Linux user per role would be stronger.

---

Built for the Company Brain Hackathon (TechEquity AI, Snowflake Silicon Valley AI Hub). MIT license.
