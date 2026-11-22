<p align="center">
  <a href="README.md">English</a> | 简体中文
</p>

# 编解码

> <sub>本文档由 Anthropic 的 Claude Fable 5.2 生成。</sub>

这是 Miyu 的一个脚本软件包，提供一件工具 `codec`，用来计算哈希，或者做编码和解码。

| 参数 | 说明 |
|---|---|
| `op` | `hash`、`encode`、`decode` |
| `input` | 要处理的文字。在 shell 里 `echo` 会多输出一个换行，如果要得到和它相同的结果，就要保留这个换行 |
| `input_format` | `hash`、`encode` 时用什么方式把 `input` 读成字节：`text`（UTF-8，默认）、`hex`、`base64` |
| `format` | `encode`、`decode` 使用的编码：`base64`、`base64url`、`hex`、`url`、`html`、`rot13` |
| `algorithms` | 只用于 `hash`：用逗号或者空格隔开，也可以写 `all`，默认是 `sha256`。可以使用 md5、sha1、sha224/256/384/512、sha3_224/256/384/512、blake2b（就是 `b2sum`）、blake2s、crc32、adler32 |

如果解码得到的字节不是 UTF-8 文字，工具会用 hex 给出结果，不会悄悄换成乱码。base64 缺少末尾的 `=` 时也可以解码。工具只使用标准库，不需要联网。
