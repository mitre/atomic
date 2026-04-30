#!/usr/bin/env python3
"""Run coverage combine/xml/report only when coverage data files exist.

Used by the coverage-ci tox environment to avoid a "No data to combine"
failure when upstream test environments did not produce any coverage data.
"""
import glob
import subprocess
import sys


def main():
    files = glob.glob('.coverage.*')
    if not files:
        print('No coverage data files found, skipping combine')
        return

    for cmd in [['coverage', 'combine'], ['coverage', 'xml'], ['coverage', 'report']]:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(
                f'Command {" ".join(cmd)!r} failed with exit code {result.returncode}',
                file=sys.stderr,
            )
            sys.exit(result.returncode)


if __name__ == '__main__':
    main()
