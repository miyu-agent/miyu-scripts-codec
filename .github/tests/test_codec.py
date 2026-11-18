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


if __name__ == "__main__":
    unittest.main()
