"""Hold the INI Master metadata up against ReadSettings in mod.cpp.

Bounty Teleportation embeds carry/BountyTeleportation.ini itself as the
INIMETA resource (see carry/src/resources.rc): the file a first run writes
and the file INI Master reads are the same bytes, with a ;@mod line and a ;@ line above each key, comments the game
ignores. Nothing here is read
from that file at runtime, so a key added to ReadSettings with no matching
line in the ini, or a default that drifts between the two, would ship with
INI Master showing the wrong thing and nothing would fail.

The code is the authority. For every key ReadSettings() reads from
[settings]:

  - it must appear in the ini under [settings], and every key the ini
    documents under [settings] must be one ReadSettings() reads;
  - the default GetPrivateProfileIntW() falls back to must equal the value
    the ini itself gives the key, since that value is both the shipped
    default and the reset INI Master would write;
  - the key's comment block must carry ";@ restart", because the plugin
    reads its ini once at startup and never again (no IniWatcher, checked
    against mod.cpp);
  - a key read as GetPrivateProfileIntW(...) != 0 must say type=bool, so
    INI Master shows a checkbox from the metadata rather than a guess.

It also checks the ";@mod" line: name matches release.json's "name", author
is Seth, url is the nexus.page from release.json, and live=0, since nothing
in mod.cpp rereads the ini while the game runs.

Exits non-zero on any mismatch, so it can gate a build.

    py -3 scripts/check_inimeta.py
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
INI = os.path.join(ROOT, "carry", "BountyTeleportation.ini")
MOD_CPP = os.path.join(ROOT, "carry", "src", "mod.cpp")
RELEASE_JSON = os.path.join(ROOT, "release.json")


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def body(src, head):
    """The brace-balanced body of the first function whose signature starts with head."""
    i = src.index(head)
    i = src.index("{", i)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    raise ValueError(head)


def parse_reader(cpp):
    """key -> (section, kind, default) from ReadSettings()."""
    out = {}
    src = body(cpp, "Settings ReadSettings()")
    for m in re.finditer(
            r's\.\w+\s*=\s*GetPrivateProfileIntW\(L"(\w+)",\s*L"(\w+)",\s*(-?\d+),\s*path\.c_str\(\)\)'
            r'(\s*!=\s*0)?;',
            src):
        section, key, default, bang = m.group(1), m.group(2), m.group(3), m.group(4)
        kind = "bool" if bang else "int"
        out[key] = (section, kind, int(default))
    for m in re.finditer(r'GetPrivateProfileStringW\(L"(\w+)",\s*L"(\w+)"', src):
        section, key = m.group(1), m.group(2)
        if key not in out:
            out[key] = (section, "string", None)
    if not out:
        raise ValueError("ReadSettings() reads no keys; the parser is probably out of date")
    return out


def parse_mod_line(text):
    m = re.search(r'^;@mod\s+(.*)$', text, re.M)
    if not m:
        return {}
    fields = {}
    for fm in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', m.group(1)):
        fields[fm.group(1)] = fm.group(2) if fm.group(2) is not None else fm.group(3)
    return fields


def parse_ini(text):
    """key -> (section, default, has_restart, type) for every key under a
    section."""
    section = None
    pending_restart = False
    pending_type = None
    keys = {}
    for line in text.splitlines():
        s = line.strip()
        sec_m = re.match(r'^\[(\w+)\]$', s)
        if sec_m:
            section = sec_m.group(1)
            pending_restart = False
            pending_type = None
            continue
        if s.startswith(";@") or s.startswith("#@"):
            if re.search(r'(^|\s)restart(\s|$)', s[2:]):
                pending_restart = True
            type_m = re.search(r'(^|\s)type=(\w+)', s[2:])
            if type_m:
                pending_type = type_m.group(2)
            continue
        if s.startswith(";") or s.startswith("#") or not s:
            if not s:
                pending_restart = False  # a blank line ends the block above a key
                pending_type = None
            continue
        kv = re.match(r'^(\w+)\s*=\s*(.*)$', s)
        if kv and section:
            keys[kv.group(1)] = (section, kv.group(2).strip(), pending_restart, pending_type)
            pending_restart = False
            pending_type = None
    return keys


def main():
    cpp = read(MOD_CPP)
    ini_text = read(INI)
    release = json.loads(read(RELEASE_JSON))

    reader = parse_reader(cpp)
    ini_keys = parse_ini(ini_text)
    mod_line = parse_mod_line(ini_text)

    errors = []

    if not mod_line:
        errors.append(";@mod: no ;@mod line found in BountyTeleportation.ini")
    else:
        if mod_line.get("name") != release.get("name"):
            errors.append(";@mod name=%r, release.json says %r" % (mod_line.get("name"), release.get("name")))
        if mod_line.get("author") != "Seth":
            errors.append(";@mod author=%r, expected Seth" % mod_line.get("author"))
        want_url = "https://www.nexusmods.com/crimsondesert/mods/%s" % release.get("nexus", {}).get("page")
        if mod_line.get("url") != want_url:
            errors.append(";@mod url=%r, expected %r" % (mod_line.get("url"), want_url))
        if mod_line.get("live") != "0":
            errors.append(";@mod live=%r, expected 0: nothing in mod.cpp rereads the ini while the game runs"
                           % mod_line.get("live"))

    for key in sorted(set(reader) - set(ini_keys)):
        errors.append("%s: ReadSettings() reads it and the ini does not document it" % key)
    for key in sorted(set(ini_keys) - set(reader)):
        errors.append("%s: the ini documents it under [%s] and ReadSettings() never reads it"
                       % (key, ini_keys[key][0]))

    for key, (section, kind, default) in reader.items():
        if key not in ini_keys:
            continue
        ini_section, ini_value, has_restart, ini_type = ini_keys[key]
        if ini_section != section:
            errors.append("%s: ReadSettings() reads [%s], the ini has it under [%s]"
                           % (key, section, ini_section))
        if kind == "bool":
            want = "1" if default else "0"
            if ini_value not in ("0", "1") or ini_value != want:
                errors.append("%s: ini default %s, GetPrivateProfileIntW falls back to %s"
                               % (key, ini_value, want))
            if ini_type != "bool":
                errors.append("%s: ;@ type=%s, the code reads it as a 0/1 switch, so type=bool"
                               % (key, ini_type))
        elif kind == "int":
            if str(default) != ini_value:
                errors.append("%s: ini default %s, GetPrivateProfileIntW falls back to %s"
                               % (key, ini_value, default))
        if not has_restart:
            errors.append("%s: no ;@ restart flag, but the plugin reads its ini once at startup only"
                           % key)

    for line in errors:
        print("error  " + line)
    print("%d keys read by ReadSettings(), %d documented in the ini, %d errors"
          % (len(reader), len(ini_keys), len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
