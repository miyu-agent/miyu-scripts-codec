# codec.py 的测试（审计 2026-11-18）。
#
# 跑法（在仓库根）：
#   python3 -I -B -m unittest discover -s .github/tests
# （不加 -t .：.github 不是合法的包名，加了 unittest 会报 Start directory is not importable。）
#
# 只用标准库；不联网（脚本本来就不联网）。HOME、XDG_*、MIYU_* 都指到临时目录。
# 放在 .github/tests/ 而不是 tests/：打包会跳过 .github，测试不会进包。

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "codec.py"


def load():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("codec_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Sandbox(unittest.TestCase):
    """每条测试一个临时目录，环境里去掉所有 MIYU_*、XDG_*。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MIYU_", "XDG_"))}
        env.update(HOME=str(root / "home"), XDG_CONFIG_HOME=str(root / "cfg"),
                   XDG_CACHE_HOME=str(root / "xdg-cache"), XDG_STATE_HOME=str(root / "xdg-state"),
                   XDG_DATA_HOME=str(root / "xdg-data"))
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = root
        self.mod = load()

    def call(self, args):
        """照 main() 跑一次：stdin 喂 JSON，返回 (退出码, 输出)。"""
        out = io.StringIO()
        code = 0
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(args))), redirect_stdout(out):
            try:
                self.mod.main()
            except SystemExit as exc:
                code = exc.code or 0
        return code, out.getvalue()


class EncodeInputFormat(Sandbox):
    # 审计 #177：do_encode 的 html、rot13 两个分支在 as_bytes(text, input_format) 之前就返回，
    # input_format=hex 被无视：hex "3c623e"（就是 "<b>"）编成 html 还是 "3c623e"，rot13 成了 "3p623r"。
    HEX_B = {"op": "encode", "input": "3c623e", "input_format": "hex"}

    def test_html_honours_hex_input(self):
        code, out = self.call(dict(self.HEX_B, format="html"))
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip(), "&lt;b&gt;")

    def test_rot13_honours_hex_input(self):
        code, out = self.call(dict(self.HEX_B, format="rot13"))
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip(), "<o>")

    # 防改坏（现在就绿）：base64、url 本来就照 hex 解了。
    def test_base64_and_url_honour_hex_input(self):
        for fmt, want in (("base64", "PGI+"), ("url", "%3Cb%3E")):
            with self.subTest(format=fmt):
                code, out = self.call(dict(self.HEX_B, format=fmt))
                self.assertEqual(code, 0, out)
                self.assertEqual(out.strip(), want)

    # 防改坏（现在就绿）：不写 input_format 时 html、rot13 照文字处理。
    def test_text_input_default(self):
        code, out = self.call({"op": "encode", "input": "<b>", "format": "html"})
        self.assertEqual(out.strip(), "&lt;b&gt;")
        code, out = self.call({"op": "encode", "input": "<b>", "format": "rot13"})
        self.assertEqual(out.strip(), "<o>")


class TopLevelType(Sandbox):
    # 审计 #176：顶层不是对象时报统一的一句，退出码 1。
    def test_non_object_args_friendly_error(self):
        for args in ([], None):
            with self.subTest(args=args):
                code, out = self.call(args)
                self.assertEqual(code, 1, out)
                self.assertIn("参数要是一个 JSON 对象", out)


class LoneSurrogate(Sandbox):
    # 审计收尾：JSON 里写 "\ud800" 这种孤立代理字符，json.load 照收，后面 encode("utf-8") 或 print 时
    # 抛 UnicodeEncodeError、打 traceback。要的是一句友好报错、退出码 1。
    # 用子进程跑：print 那一步只有真的 stdout 才会炸，StringIO 收得下代理字符。
    CASES = [
        {"op": "hash", "input": "a\ud800"},
        {"op": "hash", "input": "a", "algorithms": "x\ud800"},
        {"op": "encode", "format": "base64", "input": "\ud800"},
        {"op": "encode", "format": "html", "input": "\ud800"},
        {"op": "encode", "format": "rot13", "input": "\udc80"},
        {"op": "decode", "format": "url", "input": "\ud800"},
        {"op": "decode", "format": "html", "input": "\ud800"},
        {"op": "decode", "format": "rot13", "input": "\ud800"},
        {"op": "hash", "input": "a", "x\ud800": 1},
    ]

    def run_script(self, args):
        return subprocess.run([sys.executable, "-I", "-B", str(SCRIPT)], input=json.dumps(args),
                              capture_output=True, text=True, encoding="utf-8", timeout=30)

    def test_friendly_error_no_traceback(self):
        for args in self.CASES:
            with self.subTest(args=json.dumps(args)):
                res = self.run_script(args)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertNotIn("Traceback", res.stderr)
                self.assertIn("代理字符", res.stdout)

    # 防改坏（现在就绿）：input 要先当 hex、base64 读的，代理字符本来就落在「不是合法的 hex/base64」。
    def test_hex_and_base64_input_still_friendly(self):
        for args in ({"op": "encode", "format": "hex", "input": "\ud800", "input_format": "hex"},
                     {"op": "decode", "format": "base64", "input": "\ud800"}):
            with self.subTest(args=json.dumps(args)):
                res = self.run_script(args)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertNotIn("Traceback", res.stderr)
                self.assertTrue(res.stdout.startswith("错误："), res.stdout)

    # 防改坏（现在就绿）：合法的非 BMP 字符（JSON 里成对的代理）照常算。
    def test_surrogate_pair_is_fine(self):
        res = self.run_script({"op": "encode", "format": "hex", "input": "\ud83d\ude00"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(res.stdout.strip(), "f09f9880")


if __name__ == "__main__":
    unittest.main()
