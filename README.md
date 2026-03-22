# SGProxy

> **SGProxy 是 [gproxy](https://github.com/LeenHawk/gproxy) 的精简版**，只保留 ClaudeCode 单通道 + Anthropic 原生格式。需要多通道（Codex、OpenAI 等）或多格式转换？请使用完整版 **[gproxy](https://github.com/LeenHawk/gproxy)**。

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/leenhawk)

基于 Cloudflare Workers + Durable Objects 的 ClaudeCode 凭证代理，提供 OAuth 导入、凭证轮换、用量查看和 header-only `/v1/*` 转发。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/LeenHawk/sgproxy)

Deploy Button 会读取 [`.dev.vars.example`](/home/linhuan/develop/sgproxy/.dev.vars.example)，并在部署时提示填写必需的 `ADMIN_TOKEN` secret。

[English](./README.en.md)

## 功能特性

- **单通道 ClaudeCode** — 只代理 Anthropic ClaudeCode 请求
- **Header-only 转发** — 仅处理请求头，request/response body 原样透传
- **OAuth 导入** — 支持 OAuth2 + PKCE 导入凭证
- **自动刷新** — Token 过期前自动刷新，失败标记为 `dead`
- **用量追踪** — 跟踪 5 小时 / 7 天 / 7 天 Sonnet 限额
- **429 自动切换** — 当前请求不重放，只切换后续请求使用的凭证
- **管理后台** — 内嵌 Web UI，支持中英双语
- **公开用量页** — 无需登录即可查看凭证状态

## 技术栈

- **运行时**: Cloudflare Workers + Durable Objects (SQLite)
- **语言**: Rust -> WebAssembly
- **构建**: 本地用 `worker-build` 生成 `build/`，Deploy Button 直接使用仓库内产物

## 快速开始

看上面的 Cloudflare 按钮

## 开发

### 前置要求

- [Rust](https://rustup.rs/) 工具链
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- Cloudflare 账号

### 本地开发

```bash
git clone <repo-url> && cd sgproxy
echo 'ADMIN_TOKEN=your-secret-token' > .env
wrangler dev
```

访问 `http://localhost:8787/` 打开管理页。

### 部署

```bash
worker-build --release
wrangler deploy
```

如果没有在 Deploy Button 流程里填写，就需要在 Cloudflare Dashboard 再设置 `ADMIN_TOKEN` secret。

## 使用方式

### 添加凭证

1. **OAuth 导入** — 在后台点击 `OAuth` 页签后完成授权
2. **JSON 导入** — 在后台粘贴：
   ```json
   {
     "access_token": "sk-...",
     "refresh_token": "sk-..."
   }
   ```
3. **API 导入**
   ```bash
   curl -X POST https://your-worker.dev/api/credentials \
     -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"access_token":"sk-...","refresh_token":"sk-..."}'
   ```

### 代理请求

把客户端基地址指向：

- `https://your-worker.dev/v1/...`

代理会自动覆盖上游 `authorization`，补齐 `anthropic-version` 和必需的 `anthropic-beta`。

### 页面

- `/` 管理后台
- `/usage` 公开用量页

## API 端点

### 代理端点

| 方法 | 路径 | 说明 |
|------|------|------|
| ANY | `/v1/*` | 代理 ClaudeCode 请求 |

### 管理端点

支持 `Authorization: Bearer <ADMIN_TOKEN>` 或 `x-api-key: <ADMIN_TOKEN>`。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/public/credentials` | 公开凭证用量 |
| GET | `/api/credentials` | 列出凭证 |
| POST | `/api/credentials` | 导入凭证 |
| PUT | `/api/credentials/{id}` | 更新凭证 |
| DELETE | `/api/credentials/{id}` | 删除凭证 |
| POST | `/api/credentials/{id}/enable` | 启用凭证 |
| POST | `/api/credentials/{id}/disable` | 停用凭证 |
| GET | `/api/credentials/usage` | 查看全部用量 |
| GET | `/api/credentials/usage/{id}` | 查看单个用量 |
| POST | `/api/oauth/start` | 发起 OAuth |
| POST | `/api/oauth/callback` | 完成 OAuth |

## 项目结构

```text
src/
├── lib.rs
├── do_state.rs
├── config.rs
├── proxy.rs
├── oauth.rs
├── state.rs
└── web/
    └── index.html
```

## 社区讨论

感谢 [V2EX](https://www.v2ex.com/t/1200134#reply0) 和 [Linux.do](https://linux.do/) 以及其他社区的同好的技术反馈