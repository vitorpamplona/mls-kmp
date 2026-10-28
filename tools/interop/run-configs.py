#!/usr/bin/env python3
"""Run mlswg interop test-runner configs and report every script's result.

The test-runner (mls-implementations/interop/test-runner) runs one config per
call and prints its whole transcript. This runs each named config, leaves out
the scripts the clients can't take part in, and prints which scripts passed and
which failed, with the step and error of each failure.

  tools/interop/run-configs.py --runner PATH --configs DIR --client HOST:PORT...
      [--skip-action NAME...] [--skip-cipher-suite-changes]
      [--fresh-client CMD --fresh-port PORT] [--timeout SECONDS]
      [--results DIR] [--report out.md]
      CONFIG...

--fresh-client starts CMD before each config and stops it after, so a client
that crashes in one config doesn't fail every config after it. Exits 1 if any
script failed.
"""
import argparse, json, os, shlex, socket, subprocess, sys, time


def skip_reason(steps, actions, cipher_suite_changes):
    for step in steps:
        if step.get("action") in actions:
            return f"uses {step['action']}"
    # The runner reads both spellings, changeCipherSuite and changeCiphersuite.
    if cipher_suite_changes and '"changeciphersuite": true' in json.dumps(steps).lower():
        return "changes the ciphersuite"
    return None


def wait_for_port(port, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            socket.create_connection(("localhost", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(1)
    return False


def run_config(args, name, out_dir):
    """Returns (skipped scripts, results by script, config error or None)."""
    with open(os.path.join(args.configs, name + ".json")) as f:
        config = json.load(f)
    skipped = {}
    for script, steps in list(config["scripts"].items()):
        reason = skip_reason(steps, set(args.skip_action), args.skip_cipher_suite_changes)
        if reason:
            skipped[script] = reason
            del config["scripts"][script]
    if not config["scripts"]:
        return skipped, {}, None

    config_path = os.path.join(out_dir, name + ".config.json")
    with open(config_path, "w") as f:
        json.dump(config, f)

    client = None
    if args.fresh_client:
        with open(os.path.join(out_dir, f"{name}-client.log"), "w") as log:
            client = subprocess.Popen(shlex.split(args.fresh_client), stdout=log, stderr=subprocess.STDOUT)
    try:
        if client and not wait_for_port(args.fresh_port):
            return skipped, {}, f"the client on port {args.fresh_port} didn't start"
        cmd = [args.runner, "-suite", str(args.suite), "-fail-fast", "-config", config_path]
        for c in args.client:
            cmd += ["-client", c]
        try:
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            return skipped, {}, f"the test-runner was still running after {args.timeout} s"
    finally:
        if client:
            client.kill()
            client.wait()

    with open(os.path.join(out_dir, name + ".json"), "w") as f:
        f.write(run.stdout)
    try:
        return skipped, json.loads(run.stdout)["scripts"], None
    except (ValueError, KeyError):
        # A Go panic ends in stack frames: report its message, else the last line (log.Fatal).
        lines = run.stderr.strip().splitlines() or [f"exit {run.returncode}"]
        return skipped, {}, next((l for l in lines if l.startswith("panic:")), lines[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", required=True, help="the test-runner binary")
    ap.add_argument("--configs", required=True, help="mls-implementations/interop/configs")
    ap.add_argument("--client", action="append", required=True, help="host:port of a client, repeatable")
    ap.add_argument("--suite", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=1200, help="seconds one config may run")
    ap.add_argument("--skip-action", action="append", default=[], help="leave out the scripts with this action")
    ap.add_argument("--skip-cipher-suite-changes", action="store_true", help="leave out the scripts that move to another ciphersuite")
    ap.add_argument("--fresh-client", help="command that starts a client, run anew for each config")
    ap.add_argument("--fresh-port", type=int, help="the port --fresh-client listens on")
    ap.add_argument("--results", default=".", help="directory for the configs run, the runner's results and client logs")
    ap.add_argument("--report", help="append a markdown report to this file")
    ap.add_argument("--title", default="mlswg interop")
    ap.add_argument("configs_to_run", nargs="+", metavar="CONFIG")
    args = ap.parse_args()
    if args.fresh_client and not args.fresh_port:
        ap.error("--fresh-client needs --fresh-port")
    os.makedirs(args.results, exist_ok=True)

    lines, passed, failed = [], 0, 0
    for name in args.configs_to_run:
        skipped, results, error = run_config(args, name, args.results)
        if error:
            failed += 1
            lines.append(f"- **{name}**: FAILED to run: {error}")
        for script, runs in results.items():
            bad = next((r for r in runs if r.get("failed_step") is not None), None)
            if not runs:
                failed += 1
                lines.append(f"- **{name}/{script}: FAILED**: the runner ran it for no assignment of clients")
            elif bad is None:
                passed += 1
                lines.append(f"- {name}/{script}: passed ({len(runs)} runs)")
            else:
                failed += 1
                actors = ", ".join(f"{a}={c}" for a, c in sorted(bad["actors"].items()))
                handshake = "private" if bad.get("encrypt_flag") else "public"
                lines.append(f"- **{name}/{script}: FAILED** at step {bad['failed_step']} ({handshake} handshakes; {actors}): {bad.get('error')}")
                lines.append(f"  - step: `{' '.join(bad.get('failed_step_json', '').split())}`")
        for script, reason in skipped.items():
            lines.append(f"- {name}/{script}: skipped, {reason}")

    summary = f"{args.title}: {passed} scripts passed, {failed} failed"
    print(summary)
    print("\n".join(lines))
    if args.report:
        with open(args.report, "a") as f:
            f.write(f"### {summary}\n\n" + "\n".join(lines) + "\n\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
