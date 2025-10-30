# webtext
在cloudflare上创建一个简单workers网页，用来编辑存储简单文本信息，方便查看。可以设置密码。

1.部署与绑定步骤（快速参考）

2.在 Cloudflare Dashboard -> Workers -> Create Worker，选择模块化脚本（或直接在你的 repo 用 Wrangler）。

3.将上面脚本粘贴进去或用 wrangler 发布。

创建一个 KV Namespace（假设名字 content-kv），然后在 Worker 的设置里把它绑定为变量名 CONTENT_KV（名称必须与代码里 env.CONTENT_KV 对应）。

- Wrangler 示例 wrangler.toml 里 binding:
```
[[kv_namespaces]]
binding = "CONTENT_KV"
id = "xxxxxxxxxxxxxxxxxxxx"
```

4.在 Worker 设置 -> Variables（或 Secrets）里添加 PASSWORD。你可以：

- 直接填明文密码（Worker 会自动对其做 SHA-256），或

- 直接填 SHA-256 hex（64 个十六进制字符）。

5.可选：添加 SECRET（用于 session 签名），否则会使用 PASSWORD 的哈希作为签名密钥。

6.部署并访问 Worker 的 URL。首次访问会出现登录框，登录成功后可以查看/编辑内容并自动保存到 KV。

## 说明与安全注意

-密码比较使用 SHA-256：前端发送明文密码到 Worker（HTTPS），Worker 在服务端做 SHA-256 比较。若你想提高安全性可以改为前端先做 hash（但若仍发送 hash 也相当于密码），或升级到更复杂的认证方式（例如 OAuth / Cloudflare Access）。

-Session 使用 HMAC-SHA256 签名的 token 存在 cookie（HttpOnly & Secure），有效期可由 SESSION_TTL_SECONDS 配置（默认 86400 秒）。

-KV key 为 'document'，你可以改成其它 key 名称。
