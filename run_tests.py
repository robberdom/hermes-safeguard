#!/usr/bin/env python3
"""
Hermes SafeGuard - Clean Test Runner

Runs tests silently and outputs ONLY failed tests with their tracebacks.
Usage:
  python3 run_tests.py              # Run all tests, show only failures (or green success)
  python3 run_tests.py -v           # Verbose mode
  python3 run_tests.py -f <name>    # Run specific test matching name/pattern
"""

import io
import logging
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

# Silence background loggers during test execution
logging.disable(logging.CRITICAL)
os.environ["SAFEGUARD_TESTING"] = "true"

try:
    from verifier import ensure_test_rpc_server
    ensure_test_rpc_server()
except Exception:
    pass


def run_tests(pattern: str = "test*.py", filter_str: str | None = None, verbose: bool = False):
    loader = unittest.defaultTestLoader
    suite = loader.discover("tests", pattern=pattern)

    # Filter suite if requested
    if filter_str:
        filtered = unittest.TestSuite()
        for test in _iter_tests(suite):
            if filter_str.lower() in test.id().lower():
                filtered.addTest(test)
        suite = filtered

    total_tests = suite.countTestCases()
    if total_tests == 0:
        print(f"⚠️  No tests found matching filter: {filter_str}")
        return 0

    # Buffer stdout and stderr so passing tests don't spam the terminal with audit logs
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2 if verbose else 0)

    # Redirect stdout during run to suppress print statements from intercepted calls
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        result = runner.run(suite)

    failures = result.failures
    errors = result.errors

    if verbose:
        print(stream.getvalue())

    if not failures and not errors:
        print(f"✅ All {result.testsRun} tests passed cleanly! (0 failures, 0 errors)")
        return 0

    print("=" * 70)
    print(f"🚨 FAILED TESTS ({len(failures)} failures, {len(errors)} errors out of {result.testsRun} total)")
    print("=" * 70)

    for i, (test, tb) in enumerate(failures, 1):
        test_name = test.id()
        # Extract the short assertion failure message
        tb_lines = tb.strip().splitlines()
        short_err = tb_lines[-1] if tb_lines else "Assertion failed"
        print(f"\n[{i}] ❌ FAILURE: {test_name}")
        print(f"    Reason: {short_err}")
        print("-" * 50)
        # Indent traceback
        print("\n".join("    " + line for line in tb_lines))

    for i, (test, tb) in enumerate(errors, len(failures) + 1):
        test_name = test.id()
        tb_lines = tb.strip().splitlines()
        short_err = tb_lines[-1] if tb_lines else "Error"
        print(f"\n[{i}] 💥 ERROR: {test_name}")
        print(f"    Reason: {short_err}")
        print("-" * 50)
        print("\n".join("    " + line for line in tb_lines))

    print("\n" + "=" * 70)
    print(f"Summary: ❌ {len(failures) + len(errors)} failed, ✔️ {result.testsRun - len(failures) - len(errors)} passed")
    print("=" * 70)
    return 1


def _iter_tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


if __name__ == "__main__":
    filter_arg = None
    verbose_arg = False

    args = sys.argv[1:]
    if "-v" in args or "--verbose" in args:
        verbose_arg = True
        args = [a for a in args if a not in ("-v", "--verbose")]

    if "-f" in args:
        idx = args.index("-f")
        if idx + 1 < len(args):
            filter_arg = args[idx + 1]
    elif len(args) == 1 and not args[0].startswith("-"):
        filter_arg = args[0]

    code = run_tests(filter_str=filter_arg, verbose=verbose_arg)
    sys.exit(code)

