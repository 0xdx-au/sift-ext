#!/usr/bin/env python3
"""Dependency-free conservative security checks for public source."""
import json
import re
import subprocess
from pathlib import Path

root=Path(__file__).resolve().parents[1]
files=[s for s in subprocess.check_output(["git","ls-files","-z"],cwd=root).decode().split("\0") if s]
assert files, "No tracked files"
pin=re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
secret_file=re.compile(r"(^|/)(?:\.env(?:$|\.)|secrets?/|private/)|\.(?:pem|key|p8|p12|pfx)$",re.I)
for path in files:
    assert not secret_file.search(path), "Secret-like tracked path: "+path
    file=root/path
    assert file.is_file() and file.stat().st_size<=10_000_000, "Unexpected file: "+path
    if file.suffix==".svg":
        data=file.read_text("utf-8")
        assert not re.search(r"<\s*(?:script|foreignObject|iframe)\b",data,re.I), "Active SVG: "+path
        assert not re.search(r"(?:href|src)\s*=\s*['\"](?:https?:|data:|javascript:)",data,re.I), "External SVG resource: "+path
wf=[p for p in files if p.startswith(".github/workflows/") and p.endswith((".yml",".yaml"))]
assert wf, "No workflows"
for path in wf:
    data=(root/path).read_text("utf-8")
    assert re.search(r"(?m)^permissions:\s*$",data), "Workflow missing explicit token scope: "+path
    assert not re.search(r"(?m)^\s*(?:pull_request_target|workflow_run)\s*:",data), "Privileged trigger: "+path
    assert not re.search(r"persist-credentials:\s*true|permissions:\s*write-all",data), "Broad workflow privilege: "+path
    assert not re.search(r"(?:curl|wget)[^\n|]*\|\s*(?:sh|bash)\b",data), "Remote shell: "+path
    for action in re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)",data):
        assert pin.fullmatch(action), "Action must pin a 40-character SHA: "+path+" "+action
    if "actions/checkout@" in data:
        assert "persist-credentials: false" in data, "Checkout token persisted: "+path
for required in ["LICENSE","COMMERCIAL.md","SECURITY.md",".github/CODEOWNERS",
                 ".github/workflows/public-visibility.yml"]:
    assert required in files, "Missing governance file: "+required

manifest=root/"manifest.json"
if manifest.exists():
    m=json.loads(manifest.read_text("utf-8"))
    assert m.get("manifest_version")==3, "Manifest V3 required"
    assert int(m.get("minimum_chrome_version","0"))>=156, "Unsupported browser floor"
    assert set(m.get("permissions",[]))<={"declarativeNetRequest","storage","activeTab"}, "Unexpected permissions"
    assert m.get("incognito")=="not_allowed", "Incognito must be disabled"
    for name in ["host_permissions","optional_host_permissions","externally_connectable",
                 "content_scripts","web_accessible_resources","sandbox"]:
        assert not m.get(name), "Unexpected attack surface: "+name
    assert m.get("content_security_policy",{}).get("extension_pages")=="script-src 'self'; object-src 'self'", "CSP widened"
    trust=(root/"src/intelligence/trust.mjs").read_text("utf-8")
    assert re.search(r"\bSIGNING_PIN\s*=\s*null\s*;",trust), "Unapproved production pin"
print("Security gate passed: %d tracked files, %d pinned workflows, manifest=%s"%(len(files),len(wf),manifest.exists()))
