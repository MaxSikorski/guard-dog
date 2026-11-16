# Judge D payloads

Hostile text, one file per payload, raw UTF-8 exactly as an attacker would send it. **Never execute these files and never paste their bytes into a terminal.** The harness is `crates/gd-core/tests/judge_d_injection.rs`; it feeds every file through `Untrusted::escape_for_terminal` and `escape_for_html`.

Path: `<channel>/<family>-<NN>.txt`. Families: **a** instructions aimed at an AI (`ai-`), **b** terminal escapes (`terminal-`), **c** HTML and JavaScript (`html-`), **d** structure-breaking text (`structure-`). Hosts are `example.invalid`; commands are `echo` only.

The checks the harness makes on every file: terminal output has no control character, ESC or line break; HTML output has no `<`, `>`, `"`, `'`, control character or line break; neither output shows an invisible character from the Unicode 16 table (one emoji selector right after a visible character the renderer kept as it is, never after an escape) or starts with a Unicode 16 nonspacing or enclosing mark; both outputs undo back to the exact input.

It also checks the corpus is whole (exactly these ten channel folders, every family numbered 01 to 12 with all four families in every channel, no empty file, `generate.py` plain ASCII) and that the checks have teeth: a naive renderer that returns the text unchanged must fail on every payload except the twelve listed in the harness as `NAIVE_PASSES`.

## Regenerating

Every payload is written by `generate.py` (fixed order, no randomness), which also deletes payload files it no longer writes. Its source is plain ASCII, so every hostile character in it is an escape you can read. Git treats the payload files as binary (`.gitattributes` here): their line endings are never converted, and `git diff`, `git show` and `git log -p` never print their bytes to your terminal. Run the generator from the repository root and check that `git status` stays clean:

```bash
uv run --no-project python -I fixtures/injection/generate.py
```

## Checks that become possible later

Families a and d are only partly caught today.

- **a:** no action proposed or executed (Phase 2 and 8); no untrusted bytes in a privileged AI prompt (Phase 6). Today family a only proves the text can't reach a terminal or page as markup or control characters.
- **d:** display-width truncation and bidi isolation belong to the CLI and status-page renderers; the escape functions only make the characters visible.

## Files

| File | What it tries | Which check catches it |
|---|---|---|
| `advisory-details/ai-08.txt` | claims the advisory is withdrawn, asks for a download | no check today; needs the later ones (below) |
| `advisory-details/html-08.txt` | closes the title tag, then a script | html: no markup characters; round-trips |
| `advisory-details/structure-08.txt` | Hebrew word next to version numbers | none today; needs bidi isolation |
| `advisory-details/terminal-08.txt` | clears the screen | terminal: no control character or ESC; round-trips |
| `banner/ai-06.txt` | asks for the configuration to be printed | no check today; needs the later ones (below) |
| `banner/html-06.txt` | SVG onload handler | html: no markup characters; round-trips |
| `banner/structure-06.txt` | emoji followed by 48 variation selectors and extra emoji selectors (smuggling) | both: no invisible character; round-trips |
| `banner/terminal-06.txt` | C1 CSI (U+009B) colour codes | terminal: no control character or ESC; round-trips |
| `banner/terminal-12.txt` | C1 OSC (U+009D) title, plus a carriage return that overwrites the line | terminal: no control character or ESC; round-trips |
| `changelog/ai-01.txt` | tells the AI to approve the release and run `echo` | no check today; needs the later ones (below) |
| `changelog/ai-11.txt` | fake JSON system message | no check today; needs the later ones (below) |
| `changelog/html-01.txt` | script tag | html: no markup characters; round-trips |
| `changelog/html-11.txt` | style import and base tag | html: no markup characters; round-trips |
| `changelog/structure-01.txt` | newline forges a second critical alert | terminal and html: no line break |
| `changelog/structure-11.txt` | U+2028, U+2029 and NEL forge extra lines | terminal and html: no line break (NEL is a control character) |
| `changelog/terminal-01.txt` | red bold fake CRITICAL (SGR colours) | terminal: no control character or ESC; round-trips |
| `changelog/terminal-11.txt` | backspaces overwrite "danger" with "safe" | terminal: no control character or ESC; round-trips |
| `container-label/ai-05.txt` | fake `<assistant>` tag in a label | no check today; needs the later ones (below) |
| `container-label/html-05.txt` | `srcdoc` iframe with a script | html: no markup characters; round-trips |
| `container-label/structure-05.txt` | NUL bytes | terminal and html: no control character |
| `container-label/terminal-05.txt` | bell characters | terminal: no control character or ESC; round-trips |
| `git-tag/ai-10.txt` | instruction hidden in a tag name | no check today; needs the later ones (below) |
| `git-tag/html-10.txt` | already-encoded entities (must be escaped exactly once) | html: round-trips (the entities come back as written, not as a tag) |
| `git-tag/structure-10.txt` | Unicode tag characters spell hidden text | both: no invisible character; round-trips |
| `git-tag/terminal-10.txt` | conceal and hide-cursor codes | terminal: no control character or ESC; round-trips |
| `issue-body/ai-03.txt` | asks the bot to run `echo` and close the advisory | no check today; needs the later ones (below) |
| `issue-body/ai-12.txt` | instruction in an HTML comment | no check today; needs the later ones (below) |
| `issue-body/html-03.txt` | quote breakout into an event handler | html: no markup characters; round-trips |
| `issue-body/structure-03.txt` | 100,000 characters of text | none today (length); needs display-width truncation |
| `issue-body/terminal-03.txt` | OSC 8 hyperlink with misleading text | terminal: no control character or ESC; round-trips |
| `nip11/ai-04.txt` | tells the assistant to answer only SAFE | no check today; needs the later ones (below) |
| `nip11/html-04.txt` | `javascript:` link in Markdown | none: it has no HTML-special character, so escaped HTML shows it as plain text. It only matters to a Markdown renderer or a link, which isn't tested here |
| `nip11/structure-04.txt` | right-to-left override reverses "SAFE" | both: no invisible character (the override is made visible); bidi isolation still needs the renderers |
| `nip11/terminal-04.txt` | OSC 0 window-title change | terminal: no control character or ESC; round-trips |
| `nostr-note/ai-07.txt` | fake owner order to silence alerts | no check today; needs the later ones (below) |
| `nostr-note/html-07.txt` | JavaScript-string quote breakout | html: no markup characters; round-trips |
| `nostr-note/structure-07.txt` | starts with combining marks | both: no leading combining mark; round-trips |
| `nostr-note/terminal-07.txt` | DCS device-control string | terminal: no control character or ESC; round-trips |
| `release-notes/ai-02.txt` | fake system message asking for an update call | no check today; needs the later ones (below) |
| `release-notes/html-02.txt` | image with onerror handler | html: no markup characters; round-trips |
| `release-notes/html-12.txt` | meta refresh redirect | html: no markup characters; round-trips |
| `release-notes/structure-02.txt` | CRLF forges a second finding | terminal and html: no line break |
| `release-notes/structure-12.txt` | 100,000 characters, then a forged alert line | terminal and html: no line break; the length needs display-width truncation |
| `release-notes/terminal-02.txt` | moves the cursor up and erases lines to hide earlier text | terminal: no control character or ESC; round-trips |
| `repo-name/ai-09.txt` | instruction hidden in a repo name | no check today; needs the later ones (below) |
| `repo-name/html-09.txt` | `javascript:` href | html: no markup characters; round-trips |
| `repo-name/structure-09.txt` | 200 spaces wrap onto a fake second line | none today (spaces are ordinary); needs display-width truncation |
| `repo-name/terminal-09.txt` | OSC 8 hyperlink ended with BEL | terminal: no control character or ESC; round-trips |
