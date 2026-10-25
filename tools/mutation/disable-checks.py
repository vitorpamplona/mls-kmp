#!/usr/bin/env python3
"""Mutation testing for the validation code: does some test notice each check?

For every `require(cond)` in the chosen scopes, rewrite it as
`require(true || (cond))` (the check can no longer fail), run the
validation-focused tests, and record whether they failed ("killed") or not
("survived": no test notices that check is gone). Restores every file
afterwards, whatever happens.

  tools/mutation/disable-checks.py [--limit N] [--report out.md]

Run it in a scratch worktree: it edits sources while it runs. A mutant that
does not compile is reported as such, not as killed.
"""
import argparse, os, re, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "mls/src/commonMain/kotlin/com/vitorpamplona/mls")
# (file, function names whose bodies are mutated; None = the whole file)
SCOPES = [
    ("group/GroupValidation.kt", None),
    ("group/MlsGroup.kt", ["applyCommit", "applyProposalList", "validateProposalList", "receiveProposal",
                           "receivePublicProposal", "processPublicCommit", "decryptAndStage", "joinFromWelcome", "externalJoin"]),
    ("group/WireFormatPolicy.kt", None),
]
TESTS = ["com.vitorpamplona.mls.group.*", "com.vitorpamplona.mls.interop.*", "com.vitorpamplona.mls.fuzz.*"]


def function_ranges(text, names):
    """Character ranges of the bodies of the named functions (brace matched)."""
    ranges = []
    for name in names:
        for m in re.finditer(r"fun " + re.escape(name) + r"\(", text):
            brace = text.find("{", m.end())
            # a `= expression` body has no braces before the next fun: skip those
            eq = text.find("=", m.end())
            if brace < 0 or (0 <= eq < brace and text[m.end():eq].count("(") == text[m.end():eq].count(")") and ")" in text[m.end():eq]):
                pass
            depth, i = 0, brace
            while i < len(text):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        ranges.append((brace, i))
                        break
                i += 1
    return ranges


def requires(text, ranges):
    """(start, end) of each `require(` condition, matched to its closing parenthesis."""
    out = []
    for m in re.finditer(r"\brequire\(", text):
        if ranges is not None and not any(a <= m.start() <= b for a, b in ranges):
            continue
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        out.append((m.end(), i - 1))
    return out


def run_tests():
    cmd = ["./gradlew", ":mls:jvmTest", "-q", "--offline"] + [a for t in TESTS for a in ("--tests", t)]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    out = p.stdout + p.stderr
    if p.returncode == 0:
        return "survived"
    if re.search(r"^e: ", out, re.M) or "Compilation error" in out:
        return "does not compile"
    return "killed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--report", default=os.path.join(ROOT, "mutation-report.md"))
    args = ap.parse_args()

    mutants = []
    for rel, names in SCOPES:
        path = os.path.join(SRC, rel)
        text = open(path).read()
        ranges = None if names is None else function_ranges(text, names)
        for start, end in requires(text, ranges):
            line = text.count("\n", 0, start) + 1
            mutants.append((rel, start, end, line, text[start:end].strip().replace("\n", " ")[:110]))
    if args.limit:
        mutants = mutants[: args.limit]
    print(f"{len(mutants)} mutants", flush=True)

    results = []
    for n, (rel, start, end, line, cond) in enumerate(mutants, 1):
        path = os.path.join(SRC, rel)
        original = open(path).read()
        try:
            open(path, "w").write(original[:start] + "true || (" + original[start:end] + ")" + original[end:])
            t = time.time()
            outcome = run_tests()
        finally:
            open(path, "w").write(original)
        results.append((rel, line, cond, outcome))
        print(f"[{n}/{len(mutants)}] {outcome:>16}  {rel}:{line}  {cond}  ({time.time() - t:.0f}s)", flush=True)

    with open(args.report, "w") as f:
        killed = sum(r[3] == "killed" for r in results)
        survived = [r for r in results if r[3] == "survived"]
        f.write(f"# Disabled-check mutants\n\n{killed} killed, {len(survived)} survived, "
                f"{sum(r[3] == 'does not compile' for r in results)} did not compile, of {len(results)}.\n\n")
        f.write("## Survivors: checks no test notices\n\n")
        for rel, line, cond, _ in survived:
            f.write(f"- `{rel}:{line}` `require({cond})`\n")
    print(f"report: {args.report}")
    sys.exit(0)


if __name__ == "__main__":
    main()
