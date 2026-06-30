#!/usr/bin/env python3
"""PreToolUse hook: auto-approve compound *safe* Bash commands.

Emits a PreToolUse "allow" decision ONLY when every segment of the command
(split on top-level shell operators, quote-aware) starts with a command from
one of two editable allowlists:

  READONLY  - inherently read-only utilities (ls, grep, find, ...).
  TRUSTED   - project dev tools the user already trusts via Bash(<tool>:*)
              prefix rules (isort, black, pyright, pytest, ...). NOTE: some of
              these WRITE files (black/isort) or RUN code (pytest). They are
              auto-approved here only because the user already allowlisted them
              with :* — this just extends that trust to the compound form.

Guards (any failure => stay silent, fall through to the normal prompt):
  * no command/process substitution  $(...)  `...`  <(...)  >(...)
  * no redirect to a real file (only /dev/null and fd-dups allowed)
  * dangerous `find` primaries (-exec/-delete/...) rejected
  * whole-word blacklist net (rm/mv/tee/git/...) as parser-gap defense

`timeout` is unwrapped to check the command it wraps.

Allowing wrongly is a security incident; falling through merely shows the usual
prompt. So bias HARD toward silence: when unsure, emit nothing and exit 0.
"""
import sys
import re
import json

# --- Inherently read-only utilities (regardless of non-dangerous flags). -----
READONLY = {
    "ls", "cat", "head", "tail", "echo", "printf", "pwd", "cd", "wc", "stat",
    "file", "tree", "find", "grep", "egrep", "fgrep", "rg", "fd", "sort",
    "uniq", "cut", "tr", "diff", "jq", "yq", "column", "basename", "dirname",
    "realpath", "readlink", "which", "type", "date", "comm", "nl", "fold",
    "rev", "tac", "md5sum", "sha1sum", "sha256sum", "cksum", "hexdump", "xxd",
    "strings", "true", "test",
}

# --- Project dev tools the user trusts (already allowlisted via Bash(x:*)). ---
# These may WRITE files or RUN code. Prune anything you don't want auto-approved.
TRUSTED = {
    "isort", "black", "pyright", "pytest", "mypy", "ruff", "flake8", "pylint",
    "autopep8", "yapf", "autoflake", "pyflakes", "pycodestyle", "coverage",
}

ALLOWED = READONLY | TRUSTED

# Commands that wrap and run another command; unwrap to check the inner one.
WRAPPERS = {"timeout"}

# Whole-word safety net: if any of these appear as a token anywhere, fall
# through even if the primary gate somehow passed (parser-gap defense).
BLACKLIST = {
    "rm", "rmdir", "mv", "cp", "dd", "tee", "truncate", "shred", "ln",
    "install", "chmod", "chown", "chgrp", "mkfs", "mount", "umount", "kill",
    "pkill", "killall", "reboot", "shutdown", "sudo", "su", "git", "docker",
    "kubectl", "curl", "wget", "ssh", "scp", "rsync", "nc", "ncat", "python",
    "python3", "node", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "bash",
    "sh", "zsh", "ksh", "fish", "eval", "exec", "source", "xargs", "sed",
    "awk", "perl", "ruby", "mkdir", "touch", "crontab", "at",
}

# Dangerous find primaries that execute or mutate.
FIND_DANGER = re.compile(r"(?<!\w)-(?:delete|exec|execdir|ok|okdir|fprint|fprintf|fls)\b")

# Allowed redirects: to /dev/null (any fd, append or not) or fd duplication.
REDIR_OK = re.compile(r"(?:[0-9&]*>>?|&>>?)\s*/dev/null|[0-9]*>&[0-9-]+|&>")

DURATION = re.compile(r"^\d+(\.\d+)?[smhd]?$")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
REDIR_TOK = re.compile(r"^[0-9&]*[<>]")


def mask(s):
    """Return s with quoted/escaped spans replaced by 'x' (length preserved).

    Operator chars OUTSIDE quotes are preserved so segmentation only ever sees
    real shell control operators, never a '|' or ';' that lived inside a quote
    or after a backslash (e.g. grep "a\\|b")."""
    out = []
    i, n, q = 0, len(s), None
    while i < n:
        c = s[i]
        if q == "'":
            out.append("x" if c != "'" else c)
            if c == "'":
                q = None
            i += 1
        elif q == '"':
            if c == "\\" and i + 1 < n:
                out.append("xx")
                i += 2
            elif c == '"':
                out.append(c)
                q = None
                i += 1
            else:
                out.append("x")
                i += 1
        else:
            if c == "\\" and i + 1 < n:
                out.append("xx")
                i += 2
            elif c in ("'", '"'):
                out.append(c)
                q = c
                i += 1
            else:
                out.append(c)
                i += 1
    if q is not None:
        return None  # unbalanced quotes -> let normal flow handle it
    return "".join(out)


def command_tokens(oseg, mseg):
    """List of (orig, masked) whitespace-delimited tokens of a segment."""
    toks = []
    for m in re.finditer(r"\S+", mseg):
        s, e = m.start(), m.end()
        toks.append((oseg[s:e], mseg[s:e]))
    return toks


def effective_command(toks):
    """Basename of the effective command for a segment (unwrapping WRAPPERS).

    Skips leading VAR= assignments and redirect tokens. Returns None if no
    command word is found."""
    i, guard = 0, 0
    while i < len(toks) and guard < 50:
        guard += 1
        oword, mword = toks[i]
        if ASSIGN.match(mword) or REDIR_TOK.match(mword):
            i += 1
            continue
        name = oword.rsplit("/", 1)[-1]
        if name in WRAPPERS:
            i += 1
            # skip the wrapper's options and (for timeout) a duration token
            while i < len(toks):
                _, mw = toks[i]
                if REDIR_TOK.match(mw):
                    break
                if mw.startswith("-"):
                    i += 1
                    continue
                if name == "timeout" and DURATION.match(mw):
                    i += 1
                    continue
                break
            continue
        return name
    return None


def decide(cmd):
    masked = mask(cmd)
    if masked is None:
        return False

    # 1) No command/process substitution.
    if "$(" in masked or "`" in masked or "<(" in masked or ">(" in masked:
        return False

    # 2) Redirects: strip allowed ones; any remaining > or < is a real-file
    #    redirect -> bail.
    redir_check = REDIR_OK.sub(lambda m: "x" * len(m.group()), masked)
    if ">" in redir_check or "<" in redir_check:
        return False

    # 3) Segmentation view: neutralize allowed redirects so their stray & /
    #    digits never look like control operators.
    seg_view = REDIR_OK.sub(lambda m: "x" * len(m.group()), masked)

    # Whole-word blacklist net (defense in depth).
    for word in re.findall(r"[A-Za-z_][A-Za-z0-9_+-]*", seg_view):
        if word in BLACKLIST:
            return False

    # 4) Split on top-level operators: newline ; | || |& && &
    spans, prev = [], 0
    for m in re.finditer(r"[\n;&|]+", seg_view):
        spans.append((prev, m.start()))
        prev = m.end()
    spans.append((prev, len(cmd)))

    saw_one = False
    for start, end in spans:
        oseg = cmd[start:end]
        mseg = masked[start:end]
        if not mseg.strip():
            continue
        toks = command_tokens(oseg, mseg)
        name = effective_command(toks)
        if name is None or name not in ALLOWED:
            return False
        if name == "find" and FIND_DANGER.search(mseg):
            return False
        saw_one = True

    return saw_one


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return
    try:
        if not decide(cmd):
            return
    except Exception:
        return  # never block on a bug — just fall through to normal flow
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "safe read-only / trusted-dev-tool command (auto-allowed by allow-readonly-bash hook)",
        }
    }))


if __name__ == "__main__":
    main()
