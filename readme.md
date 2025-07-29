### 代码功能概述

这是一个部署在 Cloudflare Workers 上的网页应用，它能像 Google Authenticator 或其他验证器应用一样，安全地存储和显示基于时间的一次性密码（TOTP）。

核心功能包括：

1.  **密码保护**: 整个应用由一个主访问密码（`ACCESS_PASSWORD`）保护。
2.  **密钥管理**: 用户可以添加、删除 TOTP 密钥。密钥信息被安全地存储在 Cloudflare 的 KV 存储（`AUTH_KV`）中。
3.  **TOTP 生成**: 实时计算并显示各个服务的6位数字验证码。
4.  **易用性**:
    * 支持通过 `otpauth://` URL（通常由二维码生成）快速导入密钥。
    * 提供一键复制验证码功能。
    * 支持深色/浅色主题切换。
    * 页面每30秒自动刷新，确保验证码始终有效。

### 技术架构

* **后端**: Cloudflare Worker。这是一个无服务器（Serverless）的 JavaScript 运行环境。所有逻辑，包括请求处理、认证、KV存储交互和HTML页面生成，都在这一个 Worker 脚本中完成。
* **前端**: 动态生成的 HTML、CSS 和 JavaScript。Worker 根据请求的状态（是否已认证）直接返回相应的 HTML 页面。
* **数据存储**: Cloudflare KV。一个全局分布式的键值对存储，用于持久化保存 TOTP 的名称和密钥。

### 代码结构详解

代码主要由以下几个部分组成：

1.  **`fetch` 事件监听器**: 这是 Cloudflare Worker 的入口。所有进入的 HTTP 请求都会被这个函数捕获，并传递给 `handleRequest` 函数进行处理。

2.  **`handleRequest(request, env)`**: 核心请求处理函数。
    * `request`: 包含 HTTP 请求的所有信息（URL、方法、头信息等）。
    * `env`: 包含环境变量和绑定的服务，例如 `ACCESS_PASSWORD` 和 `AUTH_KV`。

    **逻辑流程**:
    * **处理 `POST` 请求**: 用于处理表单提交的动作。
        * 首先会验证 `password` 是否与环境变量 `ACCESS_PASSWORD` 匹配，实现操作授权。
        * 使用 `switch (action)` 来区分不同的操作：
            * `action=auth`: 仅验证密码。成功后，前端脚本会跳转到认证后的页面。
            * `action=add`: 添加新的密钥。它会接收 `name` 和 `secret`，并使用 `new TOTP(secret)` 验证密钥格式的合法性，然后存入 `AUTH_KV`。
            * `action=delete`: 删除指定的密钥。
    * **处理 `GET` 请求**: 用于展示页面。
        * 通过 URL 查询参数 `/?auth=true` 判断用户是否已经通过密码验证。
        * 如果**未认证** (`!isAuthenticated`)，则调用 `passwordFormHtml()` 返回一个密码输入登录页。
        * 如果**已认证**，则会从 `AUTH_KV` 中读取所有密钥，然后调用 `appHtml()` 生成并返回显示所有验证码的主页面。

3.  **`passwordFormHtml()`**: 一个简单的函数，返回登录页面的完整 HTML。页面包含一个密码输入框和一个提交按钮。其内置的 JavaScript 会捕获表单提交事件，将密码以 `POST` 请求发送到 `/` 进行验证，成功后重定向到 `/?auth=true`。

4.  **`appHtml(totpKeys, ACCESS_PASSWORD)`**: 生成主应用界面的函数。
    * 它接收从 KV 中取出的所有密钥 `totpKeys`。
    * 遍历 `totpKeys`，为每个密钥创建一个 `TOTP` 实例，并调用 `generate()` 方法计算出当前的6位验证码。
    * 将所有密钥的名称、验证码和操作按钮（复制、删除）渲染成 HTML 列表。
    * **内置客户端 JavaScript**:
        * `toggleTheme()`: 实现深色/浅色模式切换，并将用户的选择保存在浏览器的 `localStorage` 中。
        * `copy(text)`: 使用浏览器 `navigator.clipboard.writeText` API 实现一键复制功能。
        * `add()`: 处理添加密钥的逻辑。它支持直接输入密钥，也支持解析 `otpauth://` 格式的 URL，自动提取名称和密钥。
        * `remove(name)`: 弹出确认框，然后发送 `delete` 请求到后端。
        * `exportKeys()`: 导出功能。代码中提示了此功能在前端实现不安全，建议通过后端接口实现。
        * `parseOtpAuthUrl(url)`: 一个辅助函数，用于解析 `otpauth://` 链接。
        * `setInterval(() => location.reload(), 30000)`: **关键功能**，设置一个定时器，每30秒自动刷新整个页面，以获取最新的 TOTP 验证码（因为 TOTP 的有效期通常是30秒）。

5.  **`TOTP` 类**: 这是 TOTP 算法的 JavaScript 实现。
    * `constructor(secret)`: 构造函数接收 Base32 编码的密钥，并将其转换为字节数组。
    * `generate()`: 计算当前时间对应的计数器 (`counter`)，并调用 `generateOTP`。
    * `generateOTP(counter)`: 核心算法实现。
        1.  使用 `crypto.subtle.importKey` 导入 HMAC-SHA1 算法所需的密钥。
        2.  使用 `crypto.subtle.sign` 对基于时间的计数器执行 HMAC-SHA1 签名。
        3.  按照 [RFC 4226](https://tools.ietf.org/html/rfc4226) 中定义的动态截断（Dynamic Truncation）方法，从 HMAC 结果中提取出一个4字节的数字。
        4.  取该数字对 $10^6$ 的模，得到一个6位数的验证码，并补零以确保始终是6位。

6.  **`base32ToBytes(str)`**: 辅助函数，用于将 TOTP 标准中常用的 Base32 编码字符串解码为可供加密算法使用的字节数组 (`Uint8Array`)。

### 部署和使用

要使用这段代码，你需要：

1.  一个 Cloudflare 账户。
2.  创建一个新的 Worker。
3.  将此代码粘贴到 Worker 编辑器中。
4.  创建一个 KV 命名空间，并将其绑定到此 Worker，绑定名称为 `AUTH_KV`。
5.  在 Worker 的设置中，添加一个名为 `ACCESS_PASSWORD` 的环境变量，并设置你的访问密码。
6.  部署 Worker。之后你就可以通过 Worker 的 URL 访问你的个人 TOTP 管理器了。
