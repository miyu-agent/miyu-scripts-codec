#!/usr/bin/env python3
# Display name: Encode, decode, hash
# 显示名称：编解码
# Description: Hash text or bytes, or encode/decode base64, base64url, hex, url, html entities, rot13. Exact bytes, no guessing.
# 描述：算哈希（md5、sha 系列、blake2、crc32 等），或做 base64、hex、url、html 实体、rot13 的编码和解码。
# Timeout: 20
# Need load: no
# Clicall: yes
# Parameters:
# {"type": "object", "properties": {
#   "op": {"type": "string", "enum": ["hash", "encode", "decode"]},
#   "input": {"type": "string", "description": "The text to work on. A shell `echo` adds a trailing newline: keep it to match."},
#   "input_format": {"type": "string", "enum": ["text", "hex", "base64"], "description": "hash and encode: how to read input as bytes. Default text (UTF-8)."},
#   "format": {"type": "string", "enum": ["base64", "base64url", "hex", "url", "html", "rot13"], "description": "encode and decode: the encoding. Required for those."},
#   "algorithms": {"type": "string", "description": "hash: names separated by commas or spaces, or all. Default sha256. md5 sha1 sha224 sha256 sha384 sha512 sha3_224 sha3_256 sha3_384 sha3_512 blake2b (= b2sum) blake2s crc32 adler32."}
# }, "required": ["op", "input"]}

import base64
import binascii
import codecs
import hashlib
import html
import json
import sys
import urllib.parse
import zlib

ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256",
              "sha3_384", "sha3_512", "blake2b", "blake2s", "crc32", "adler32"]
ALIASES = {"b2sum": "blake2b", "blake2b512": "blake2b", "blake2s256": "blake2s"}
FORMATS = ["base64", "base64url", "hex", "url", "html", "rot13"]
MAX_INPUT = 1 << 20


class Failure(Exception):
    pass


def from_hex(text):
    digits = "".join(text.split())
    if digits[:2].lower() == "0x":
        digits = digits[2:]
    try:
        return bytes.fromhex(digits)
    except ValueError:
        raise Failure("不是合法的 hex：只能有 0-9、a-f，位数要是偶数") from None


def from_base64(text, urlsafe=False):
    compact = "".join(text.split())
    compact += "=" * (-len(compact) % 4)  # 补上省掉的等号
    try:
        if urlsafe:
            return base64.b64decode(compact.translate(str.maketrans("-_", "+/")), validate=True)
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        alphabet = "A-Z a-z 0-9 - _" if urlsafe else "A-Z a-z 0-9 + /"
        raise Failure(f"不是合法的 {'base64url' if urlsafe else 'base64'}：字符只能是 {alphabet} 和末尾的 =") from None


def as_bytes(text, input_format):
    if input_format == "text":
        return text.encode("utf-8")
    if input_format == "hex":
        return from_hex(text)
    if input_format == "base64":
        return from_base64(text)
    raise Failure(f"input_format 只能是 text、hex、base64，收到 {input_format!r}")


def show_text(data):
    """解出来的字节：是 UTF-8 就照文字给，不是就给 hex，不悄悄替换成 �。"""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"（不是 UTF-8 文字，{len(data)} 字节，hex）{data.hex()}"


def digest(name, data):
    if name == "crc32":
        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    if name == "adler32":
        return f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
    return hashlib.new(name, data).hexdigest()


def do_hash(args, text):
    data = as_bytes(text, args.get("input_format") or "text")
    wanted = str(args.get("algorithms") or "sha256").replace(",", " ").split()
    if [w.lower() for w in wanted] == ["all"]:
        wanted = ALGORITHMS
    names, unknown = [], []
    for raw in wanted:
        name = raw.lower().replace("-", "_")
        name = ALIASES.get(name, name)
        if name in ALGORITHMS:
            if name not in names:
                names.append(name)
        else:
            unknown.append(raw)
    if unknown:
        raise Failure(f"不认识的算法：{', '.join(unknown)}。能用的：{' '.join(ALGORITHMS)}（b2sum 就是 blake2b），或者 all")
    lines = [f"{len(data)} 字节"]
    lines += [f"{name}: {digest(name, data)}" for name in names]
    return "\n".join(lines)


def need_format(args):
    fmt = args.get("format")
    if fmt not in FORMATS:
        raise Failure(f"format 要写，能用的：{'、'.join(FORMATS)}")
    return fmt


def do_encode(args, text):
    fmt = need_format(args)
    if fmt == "html":
        return html.escape(text, quote=True)
    if fmt == "rot13":
        return codecs.encode(text, "rot_13")
    data = as_bytes(text, args.get("input_format") or "text")
    if fmt == "base64":
        return base64.b64encode(data).decode()
    if fmt == "base64url":
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    if fmt == "hex":
        return data.hex()
    return urllib.parse.quote_from_bytes(data, safe="")


def do_decode(args, text):
    fmt = need_format(args)
    if fmt == "base64":
        return show_text(from_base64(text))
    if fmt == "base64url":
        return show_text(from_base64(text, urlsafe=True))
    if fmt == "hex":
        return show_text(from_hex(text))
    if fmt == "url":
        return show_text(urllib.parse.unquote_to_bytes(text))
    if fmt == "html":
        return html.unescape(text)
    return codecs.decode(text, "rot_13")


OPS = {"hash": do_hash, "encode": do_encode, "decode": do_decode}


def known_params():
    """开头 Parameters 里写的参数名：不认识的参数直接报错，免得写错的名字被悄悄当成没给。"""
    lines, inside = [], False
    with open(__file__, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("#"):
                break
            if line.startswith("# Parameters:"):
                inside = True
            elif inside:
                lines.append(line[1:])
    return set(json.loads("".join(lines)).get("properties", {}))


def reject_unknown(args):
    unknown = sorted(set(args) - known_params())
    if unknown:
        print(f"错误：不认识的参数：{'、'.join(unknown)}。能用的：{'、'.join(sorted(known_params()))}")
        sys.exit(1)


def main():
    try:
        args = json.load(sys.stdin)
        if not isinstance(args, dict):
            raise ValueError("要一个 JSON 对象")
    except ValueError as exc:
        print(f"错误：参数不是 JSON 对象：{exc}")
        sys.exit(1)
    reject_unknown(args)
    try:
        op = args.get("op")
        if op not in OPS:
            raise Failure("op 只能是 hash、encode、decode")
        text = args.get("input")
        if not isinstance(text, str):
            raise Failure("input 要写，是一段文字")
        if len(text) > MAX_INPUT:
            raise Failure(f"input 太长（{len(text)} 字），上限 {MAX_INPUT}")
        print(OPS[op](args, text))
    except Failure as exc:
        print(f"错误：{exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
