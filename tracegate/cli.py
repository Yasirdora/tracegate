import argparse
import json
import os
from .scan import scan


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspect test artifact text locally before upload. No redaction or safety certification.')
    parser.add_argument('artifact', help='ZIP trace, JSON report, or UTF-8 text file')
    parser.add_argument('--secret-env', action='append', default=[], metavar='NAME', help='Read an exact known secret from this environment variable (repeatable)')
    parser.add_argument('--text-only', action='store_true', help='Explicitly exclude known image/video extensions from blocking completeness')
    parser.add_argument('--format', choices=['json', 'text'], default='text')
    args = parser.parse_args(argv)
    secrets = [os.environ.get(name, '') for name in args.secret_env]
    if any(len(s) < 4 for s in secrets):
        # Do not echo variable names or values.
        print('Configuration error: each requested secret must exist and contain at least four characters.')
        return 2
    report = scan(args.artifact, known=secrets, text_only=args.text_only)
    if args.format == 'json':
        print(json.dumps(report, indent=2))
    else:
        print('TraceGate: ' + report['status'])
        print('Scope: ' + report['scope'])
        print(f"Inspected {report['scannedMembers']} members / {report['scannedBytes']} bytes")
        for finding in report['findings']:
            print(f"  member {finding['member']}, line {finding['line']}: {finding['rule']} [value withheld]")
        for item in report['uninspected']:
            print(f"  member {item['member']}: {item['reason']}")
        print('No findings is not a guarantee of no sensitive data.')
    return {'no-findings-in-scope': 0, 'findings': 1, 'incomplete': 2}[report['status']]
