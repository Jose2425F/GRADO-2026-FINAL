"""Saneamiento previo a persistencia; recibos con conteos, nunca valores omitidos."""
from collections import Counter
import base64
import json
import os
import re
from urllib.parse import quote

VERSION = "persistence-sanitization-1"
ANSI = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")
CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "api_key", "apikey", "access_token",
                  "refresh_token", "authorization", "cookie", "set-cookie"}
TOKEN = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}",re.I)
ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*([^\s,;<>]+)")


def known_secrets():
    values=set()
    for key,value in os.environ.items():
        if len(value)>=8 and (re.search(r"PASSWORD|PASSWD|SECRET|API_KEY|ACCESS_TOKEN|OBSERVER_TOKEN",key)
                              or key.startswith(("LAB_NOVA_","LAB_ACTUAL_","LAB_SUITE_","LAB_SWEEP_"))):
            values.update([value,quote(value,safe=""),base64.b64encode(value.encode()).decode()])
    return sorted(values,key=len,reverse=True)


def sanitize(value, *, secrets=None):
    counts=Counter()
    secrets=known_secrets() if secrets is None else secrets
    def text(value):
        # Redact both before and after removing controls, so escape sequences
        # cannot split a credential to bypass the second pass.
        for secret in secrets:
            if secret:
                counts['known_secret']+=value.count(secret)
                value=value.replace(secret,'[REDACTED]')
        value,n=ANSI.subn('',value);counts['terminal_sequence']+=n
        value,n=CONTROLS.subn('',value);counts['control_character']+=n
        for secret in secrets:
            if secret:
                counts['known_secret']+=value.count(secret)
                value=value.replace(secret,'[REDACTED]')
        value,n=TOKEN.subn('[REDACTED]',value);counts['token']+=n
        value,n=ASSIGNMENT.subn(lambda m:m.group(1)+'=[REDACTED]',value);counts['credential_assignment']+=n
        return value
    def walk(value):
        if isinstance(value,str):return text(value)
        if isinstance(value,dict):
            result={}
            for key,item in value.items():
                clean_key=text(key) if isinstance(key,str) else key
                if clean_key in result:raise ValueError('sanitization_key_collision')
                if isinstance(clean_key,str) and clean_key.lower() in SENSITIVE_KEYS and item is not None:
                    counts['sensitive_field']+=1
                    result[clean_key]='[REDACTED]'
                else:result[clean_key]=walk(item)
            return result
        if isinstance(value,(list,tuple)):return [walk(item) for item in value]
        return value
    cleaned=walk(value)
    return cleaned,{key:n for key,n in counts.items() if n}


def sanitize_evidence(data, extension):
    if extension=='pcap':
        # A packet capture is a binary measurement: never strip its control bytes.
        if any(secret.encode() in data for secret in known_secrets()):
            raise ValueError('binary_evidence_contains_known_secret')
        return data,{}
    raw=data.decode('utf-8',errors='strict')
    if extension=='json':
        clean,counts=sanitize(json.loads(raw))
        return (json.dumps(clean,ensure_ascii=False,sort_keys=True).encode() if counts else data),counts
    clean,counts=sanitize(raw)
    return clean.encode(),counts


def omission_receipt(counts):
    return {'version':VERSION,'omissions':counts,'omitted_values_retained':False}
