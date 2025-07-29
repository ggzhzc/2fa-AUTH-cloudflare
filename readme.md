好的，当然可以。

这是一个美化后的 Markdown 版本，结构更清晰，并使用了代码块以便于复制代码。

-----

# Cloudflare TOTP 网页验证器部署指南

这是一个部署在 Cloudflare Workers 上的网页应用，它能像 Google Authenticator 或其他验证器应用一样，安全地存储和显示基于时间的一次性密码（TOTP）。

## 🚀 核心功能

  * **🔑 密码保护**: 整个应用由一个主访问密码（环境变量 `ACCESS_PASSWORD`）提供安全保障。
  * **💾 密钥管理**: 用户可以随时添加、删除 TOTP 密钥。所有密钥信息被安全地存储在 Cloudflare 的 **D1 数据库**中。
  * **⏱️ TOTP 生成**: 实时计算并显示各个服务的6位数字验证码。
  * **✨ 易用性**:
      * 支持通过 `otpauth://` URL（通常由二维码生成）快速导入新密钥。
      * 提供一键复制验证码到剪贴板的功能。
      * 支持深色/浅色主题切换。
      * 页面每30秒自动刷新，确保验证码始终有效。

## 🛠️ 部署与使用

要部署和使用此应用，您需要一个 Cloudflare 账户，然后遵循以下步骤：

1.  **创建 Worker**:

      * 登录到您的 Cloudflare 账户。
      * 导航至 `Workers & Pages` \> `Create application` \> `Create Worker`。
      * 为您的 Worker 命名并部署。
      * 将项目代码粘贴到 Worker 编辑器中。

2.  **创建 D1 数据库**:

      * 在 Cloudflare 仪表板中，导航至 `D1` 并创建一个新的数据库。
      * 数据库名称可以任意指定。

3.  **初始化数据表**:

      * 进入您刚刚创建的 D1 数据库，在控制台（Console）中执行以下 SQL 命令来创建用于存储密钥的表：

    <!-- end list -->

    ```sql
    CREATE TABLE totp_keys (
      name TEXT PRIMARY KEY,
      secret TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ```

4.  **绑定数据库到 Worker**:

      * 回到您的 Worker 项目，点击 `Settings` \> `Variables`。
      * 在 `D1 Database Bindings` 部分，点击 `Add binding`。
      * 设置绑定变量名称为 **`DB`** (注意：必须为大写)。
      * 选择您在第2步创建的数据库。
      * 点击 `Save` 保存绑定。

5.  **设置访问密码**:

      * 在同一页的 `Environment Variables` 部分，点击 `Add variable`。
      * 设置变量名称为 **`ACCESS_PASSWORD`**。
      * 在 `Value` 字段中输入您想要设置的访问密码，然后点击 `Encrypt` 加密保存。

6.  **部署和访问**:

      * 完成以上设置后，回到 Worker 编辑器页面，点击 `Deploy`。
      * 部署成功后，您就可以通过 Worker 的 URL 访问您的个人 TOTP 管理器了。
