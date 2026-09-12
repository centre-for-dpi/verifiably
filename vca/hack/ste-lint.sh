#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# ste-lint.sh: check Markdown files and proto comments against the
# Simplified Technical English rules of vca/docs/style.md.
#
# Usage:
#   hack/ste-lint.sh [--words FILE] [--fix-dashes] [--max-words N] FILE...
#
# Rules:
#   long-sentence  a sentence has more than 20 words
#   dash           an em dash or an en dash
#   passive        a form of "to be" followed by a past participle
#   banned-word    a word from hack/ste-words.txt
#
# The script skips fenced code blocks, inline code, URLs, and product
# names such as "Inji Verify" (two capitalised words in a row).
# Output is "file:line: rule: detail", one finding per line.
# Exit status is 1 when it finds at least one problem, else 0.
#
# --fix-dashes replaces each dash with a comma in place. A dash between
# two numbers becomes " to ". The check runs again after the fix.

set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
words_file="$script_dir/ste-words.txt"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ste-lint: python3 is not installed" >&2
  exit 2
fi

STE_WORDS_FILE="$words_file" exec python3 - "$@" <<'PY'
import os
import re
import sys

MAX_WORDS = 20

IRREGULAR = {
    "become", "begun", "bound", "bought", "brought", "built", "caught",
    "chosen", "come", "cut", "done", "driven", "drawn", "eaten", "fed",
    "felt", "forbidden", "forgotten", "found", "given", "gone", "gotten",
    "had", "held", "hidden", "hit", "hurt", "kept", "known", "laid", "led",
    "left", "let", "lost", "made", "meant", "met", "paid", "put", "read",
    "rewritten", "run", "said", "seen", "sent", "set", "shown", "shut",
    "sold", "spent", "split", "spoken", "stored", "taken", "taught", "told",
    "thought", "thrown", "understood", "won", "written", "led",
}
NOT_PARTICIPLE = {
    "bed", "embed", "exceed", "feed", "fled", "hundred", "indeed",
    "need", "proceed", "red", "seed", "shed", "shred", "speed", "succeed",
    "wed", "unused",
}
BE_FORMS = {"is", "are", "was", "were", "be", "been", "being"}

DASH_RE = re.compile("[\u2013\u2014]")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
URL_RE = re.compile(r"(https?://|www\.)\S+|<[^>\s]+@[^>\s]+>")
LINK_TARGET_RE = re.compile(r"\]\([^)]*\)")
HTML_TAG_RE = re.compile(r"<[^>]+>")
WORD_RE = re.compile(r"[A-Za-z][A-Za-z'\-]*")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
HEADING_RE = re.compile(r"^\s*#{1,6}\s+")
LIST_RE = re.compile(r"^\s*([-*+]|\d+[.)])\s+")
TABLE_RE = re.compile(r"^\s*\|")
TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}")
BADGE_RE = re.compile(r"!\[[^\]]*\]")


def load_words(path):
    rules = []
    if not os.path.exists(path):
        return rules
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "->" not in line:
                continue
            bad, good = [p.strip() for p in line.split("->", 1)]
            pattern = r"(?<![\w-])" + re.escape(bad).replace(r"\ ", r"\s+")
            if bad[-1].isalnum():
                pattern += r"(?![\w-])"
            rules.append((bad, good, re.compile(pattern, re.IGNORECASE)))
    return rules


def is_participle(word):
    w = word.lower().strip("'")
    if w in IRREGULAR:
        return True
    if w in NOT_PARTICIPLE:
        return False
    return len(w) >= 4 and w.endswith("ed")


def is_proper_noun(text, match):
    """A capitalised match after another capitalised word is a name."""
    if not match.group(0)[0].isupper():
        return False
    before = text[: match.start()].split()
    return bool(before) and before[-1][0].isupper()


def strip_markup(text):
    text = INLINE_CODE_RE.sub(" ", text)
    text = BADGE_RE.sub(" ", text)
    text = LINK_TARGET_RE.sub("] ", text)
    text = URL_RE.sub(" ", text)
    text = HTML_TAG_RE.sub(" ", text)
    return text


def prose_lines(path, lines):
    """Yield (line_no, text, new_block) for prose, skipping code."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".proto":
        for no, line in enumerate(lines, 1):
            m = re.search(r"//+\s?(.*)$", line)
            if m and "://" not in line[: m.start()]:
                yield no, m.group(1), False
            else:
                yield no, "", True
        return
    in_fence = False
    for no, line in enumerate(lines, 1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            yield no, "", True
            continue
        if in_fence:
            continue
        if not line.strip():
            yield no, "", True
            continue
        new_block = bool(HEADING_RE.match(line) or LIST_RE.match(line))
        if TABLE_RE.match(line):
            if TABLE_SEP_RE.match(line):
                continue
            for cell in line.strip().strip("|").split("|"):
                yield no, strip_markup(cell) + " .", True
            continue
        text = HEADING_RE.sub("", line)
        text = LIST_RE.sub("", text)
        yield no, strip_markup(text), new_block


def check_sentences(items, findings, path):
    sentence = []
    start = None
    for no, text, new_block in items:
        if new_block:
            if len(sentence) > MAX_WORDS:
                findings.append((path, start, "long-sentence",
                                 "%d words" % len(sentence)))
            sentence, start = [], None
        for tok in text.split():
            if start is None:
                start = no
            if WORD_RE.search(tok):
                sentence.append(tok)
            if tok.rstrip("\"')*_]").endswith((".", "!", "?", ":")):
                if len(sentence) > MAX_WORDS:
                    findings.append((path, start, "long-sentence",
                                     "%d words" % len(sentence)))
                sentence, start = [], None
    if len(sentence) > MAX_WORDS:
        findings.append((path, start, "long-sentence",
                         "%d words" % len(sentence)))


def check_line_rules(items, rules, findings, path):
    for no, text, _ in items:
        if not text:
            continue
        words = WORD_RE.findall(text)
        for i in range(len(words) - 1):
            a, b = words[i].lower(), words[i + 1]
            if a in BE_FORMS and is_participle(b):
                findings.append((path, no, "passive", "%s %s" % (words[i], b)))
            elif a in BE_FORMS and b.lower() == "being" and i + 2 < len(words) \
                    and is_participle(words[i + 2]):
                findings.append((path, no, "passive",
                                 "%s being %s" % (words[i], words[i + 2])))
        for bad, good, rx in rules:
            for m in rx.finditer(text):
                if is_proper_noun(text, m):
                    continue
                findings.append((path, no, "banned-word",
                                 "%s -> %s" % (bad, good)))
                break


def check_dashes(path, lines, findings):
    for no, line in enumerate(lines, 1):
        if DASH_RE.search(line):
            findings.append((path, no, "dash", "use a comma, colon, or full stop"))


def fix_dashes(path, lines):
    out = []
    for line in lines:
        line = re.sub(r"(\d)\s*[\u2013\u2014]\s*(\d)", r"\1 to \2", line)
        line = re.sub(r"\s*[\u2013\u2014]+\s*", ", ", line)
        out.append(line)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(out))
    return out


def lint_file(path, rules, fix):
    findings = []
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    if fix:
        lines = fix_dashes(path, lines)
    check_dashes(path, lines, findings)
    items = list(prose_lines(path, lines))
    check_sentences(items, findings, path)
    check_line_rules(items, rules, findings, path)
    return findings


def main(argv):
    global MAX_WORDS
    words_file = os.environ.get("STE_WORDS_FILE", "")
    fix = False
    paths = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--fix-dashes":
            fix = True
        elif arg == "--words":
            i += 1
            words_file = argv[i]
        elif arg == "--max-words":
            i += 1
            MAX_WORDS = int(argv[i])
        elif arg in ("-h", "--help"):
            print("usage: ste-lint.sh [--words FILE] [--fix-dashes] "
                  "[--max-words N] FILE...")
            return 0
        else:
            paths.append(arg)
        i += 1
    if not paths:
        print("ste-lint: no files given", file=sys.stderr)
        return 2
    rules = load_words(words_file)
    total = 0
    for path in paths:
        for f in sorted(lint_file(path, rules, fix), key=lambda x: (x[1], x[2])):
            print("%s:%d: %s: %s" % f)
            total += 1
    if total:
        print("ste-lint: %d finding(s)" % total, file=sys.stderr)
        return 1
    return 0


sys.exit(main(sys.argv[1:]))
PY
