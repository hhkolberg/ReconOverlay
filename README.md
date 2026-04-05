# ReconOverlay

**Focus on enumeration while ReconOverlay watches what is visible on screen, detects software names and version numbers, and looks for relevant vulnerabilities and exploit references in real time.**

ReconOverlay is built to help during CTFs, labs, and hands-on assessments by turning visible software clues into useful vulnerability context. If a setup window, admin panel, banner, dashboard, or login page exposes a product name or version number, ReconOverlay can detect it, search for related CVEs and exploit references, and show you what may be worth investigating next.

Instead of interrupting your workflow to manually search every clue, you can stay focused on recon while the tool does that correlation work in the background.

## Why this is useful

During a CTF or lab, small details often matter:

- a setup wizard reveals an exact version
- a login page leaks a product name
- a dashboard footer exposes a framework
- a terminal banner shows a service version
- an admin panel quietly tells you what is running

Those clues are valuable, but manually stopping to search each one breaks momentum.

ReconOverlay is designed to reduce that friction.

It helps shorten the gap between **spotting a clue** and **understanding whether that clue matters**.

## What it does

ReconOverlay monitors the windows you choose and scans visible content for recognizable software names and version strings.

When it finds something useful, it can:

- detect the software name
- detect the version number
- search for related CVEs
- collect public exploit references
- help prioritize what looks most interesting first

The goal is simple: keep you focused on enumeration while the tool turns visible on-screen clues into actionable recon context.

## How it works

The workflow is straightforward:

1. Select one or more windows to monitor.
2. ReconOverlay captures visible content from those windows.
3. OCR is used to extract readable text.
4. The tool looks for known software names and version numbers.
5. If it finds a match, it searches relevant sources for CVEs and exploit references.
6. Results are shown in the interface so you can quickly judge what looks worth investigating.

## Learning mode

ReconOverlay also supports manual learning.

If a product name or version number consistently appears in a specific area of a window, you can mark those regions and help the tool read them more reliably in future scans.

This makes the tool more accurate for:

- installers
- setup dialogs
- CMS panels
- admin dashboards
- software pages with stable layouts

## External software catalog

ReconOverlay uses an external software catalog stored next to the script.

That means you can:

- add new software manually
- store optional versions
- store aliases
- keep notes
- move the tool to another machine without losing your added entries

This makes the catalog portable and easy to maintain.

## Practical use case

ReconOverlay is meant for practical offensive workflows, especially in:

- CTFs
- lab environments
- isolated testing setups
- practice boxes
- hands-on recon sessions

It is not meant to replace real enumeration.

It is meant to support it.

## What it is not

ReconOverlay is **not** an automated exploitation framework.

It does **not** prove exploitability on its own.

It helps surface leads faster, but you still need to:

- validate findings
- confirm version accuracy
- confirm target context
- verify exploitability manually

## In short

ReconOverlay does one thing very well:

**it turns visible on-screen software clues into actionable recon context without forcing you to stop what you are doing.**
