# 编解码

Miyu 脚本包，带一件工具 `codec`：算哈希，或者做编码、解码。

| 参数 | 说明 |
|---|---|
| `op` | `hash`、`encode`、`decode` |
| `input` | 要处理的文字。shell 里 `echo` 会带一个换行，要对上就保留它 |
| `input_format` | `hash`、`encode` 时怎么把 `input` 读成字节：`text`（UTF-8，默认）、`hex`、`base64` |
| `format` | `encode`、`decode` 用的编码：`base64`、`base64url`、`hex`、`url`、`html`、`rot13` |
| `algorithms` | `hash` 用：逗号或空格隔开，或者 `all`，默认 `sha256`。md5、sha1、sha224/256/384/512、sha3_224/256/384/512、blake2b（就是 `b2sum`）、blake2s、crc32、adler32 |

解出来的字节不是 UTF-8 文字时照 hex 给，不悄悄换成乱码。base64 少了末尾的 `=` 也认。只用标准库，不联网。
