"""Never emit values, snippets, object keys, filenames or exception messages.

Member identifiers are ordinals in archive order. The caller keeps the original
artifact to locate a finding. This avoids copying secrets embedded in filenames
or arbitrary JSON keys into a report.
"""
import json
import re
import stat
import zipfile
from pathlib import Path
from urllib.parse import quote

SENSITIVE = {'password', 'passwd', 'authorization', 'proxyauthorization',
             'cookie', 'setcookie', 'accesstoken', 'refreshtoken', 'apikey',
             'clientsecret'}
MEDIA = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.mp4', '.webm'}
TEXT = {'.json', '.jsonl', '.trace', '.network', '.stacks', '.txt', '.log', '.html', '.md', '.xml', '.csv'}


def normalized(value):
    return re.sub('[^a-z]', '', value.lower())


def populated(value):
    return value is not None and value != '' and value != [] and value != {}


def inspect_text(text, member, known):
    findings = []
    seen = set()

    def add(rule, line):
        key = (rule, line)
        if key not in seen:
            seen.add(key)
            findings.append({'member': member, 'line': line, 'rule': rule})

    def walk(value, line, depth=0):
        if depth > 100:
            raise ValueError('depth')
        if isinstance(value, dict):
            for key, child in value.items():
                if normalized(key) in SENSITIVE and populated(child):
                    add('credential-field', line)
                walk(child, line, depth + 1)
            # Playwright HAR-style headers/cookies use name/value objects.
            if isinstance(value.get('name'), str) and populated(value.get('value')):
                if normalized(value['name']) in SENSITIVE:
                    add('credential-field', line)
            # All populated cookie values are potentially sensitive.
            cookies = value.get('cookies')
            if isinstance(cookies, list) and any(isinstance(c, dict) and populated(c.get('value')) for c in cookies):
                add('cookie-value', line)
        elif isinstance(value, list):
            for child in value:
                walk(child, line, depth + 1)

    for line, content in enumerate(text.splitlines(), 1):
        for secret in known:
            variants = {secret, json.dumps(secret)[1:-1], quote(secret, safe='')}
            if any(v in content for v in variants):
                add('known-secret', line)
        if re.search(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}', content):
            add('bearer-token', line)
        if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', content):
            add('private-key', line)
    # Whole JSON supports pretty-printed reports; otherwise JSONL trace events.
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if doc is not None:
        walk(doc, 1)
    else:
        for line, content in enumerate(text.splitlines(), 1):
            try:
                doc = json.loads(content)
            except json.JSONDecodeError:
                continue
            walk(doc, line)
    return findings


def scan(path, known=(), text_only=False, max_member=8*1024*1024,
         max_total=64*1024*1024, max_members=2000):
    report = {'schemaVersion': 1, 'scope': 'text-only' if text_only else 'artifact',
              'findings': [], 'uninspected': [], 'scannedMembers': 0,
              'scannedBytes': 0, 'status': 'incomplete'}

    def skip(member, reason):
        report['uninspected'].append({'member': member, 'reason': reason})

    def consume(data, member, suffix):
        if suffix in MEDIA:
            skip(member, 'media-not-inspected')
            return
        try:
            content = data.decode('utf-8')
        except UnicodeDecodeError:
            skip(member, 'non-utf8')
            return
        if '\x00' in content:
            skip(member, 'binary-content')
            return
        try:
            found = inspect_text(content, member, known)
        except (ValueError, RecursionError):
            skip(member, 'structured-content-limit')
            return
        report['findings'].extend(found)
        report['scannedMembers'] += 1
        report['scannedBytes'] += len(data)

    try:
        p = Path(path)
        if p.is_symlink() or not p.is_file():
            skip(0, 'not-a-regular-file')
        elif zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as archive:
                members = archive.infolist()
                total = 0
                if len(members) > max_members:
                    skip(0, 'member-count-limit')
                else:
                    for i, info in enumerate(members, 1):
                        if info.is_dir():
                            continue
                        if stat.S_ISLNK(info.external_attr >> 16):
                            skip(i, 'symlink'); continue
                        if info.flag_bits & 1:
                            skip(i, 'encrypted-member'); continue
                        if info.file_size > max_member or total + info.file_size > max_total:
                            skip(i, 'byte-limit'); continue
                        total += info.file_size
                        # Read into bounded memory; never extract archive paths.
                        try:
                            with archive.open(info) as stream:
                                data = stream.read(max_member + 1)
                            if len(data) > max_member:
                                skip(i, 'byte-limit'); continue
                            if data.startswith(b'PK\x03\x04'):
                                skip(i, 'nested-archive'); continue
                            consume(data, i, Path(info.filename).suffix.lower())
                        except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                            skip(i, 'unreadable-member')
        elif p.suffix.lower() not in TEXT:
            skip(0, 'unsupported-input')
        elif p.stat().st_size > min(max_member, max_total):
            skip(0, 'byte-limit')
        else:
            with p.open('rb') as stream:
                data = stream.read(max_member + 1)
            if len(data) > max_member:
                skip(0, 'byte-limit')
            else:
                consume(data, 0, p.suffix.lower())
    except (OSError, ValueError, zipfile.BadZipFile):
        skip(0, 'unreadable-input')
    blockers = [item for item in report['uninspected']
                if not (text_only and item['reason'] == 'media-not-inspected')]
    if blockers or report['scannedMembers'] == 0:
        report['status'] = 'incomplete'
    elif report['findings']:
        report['status'] = 'findings'
    else:
        report['status'] = 'no-findings-in-scope'
    return report
