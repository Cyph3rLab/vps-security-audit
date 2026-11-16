# VPS Security Audit

面向 **Ubuntu / Debian** VPS 的只读安全基线审计脚本。脚本检查系统更新、SSH、账号权限、防火墙与监听端口、暴力破解防护、内核参数、关键文件权限、服务与计划任务、轻量级入侵迹象，以及 Docker 容器配置，并生成 Markdown 审计报告和 AI 加固提示词。

> **安全提示：** 报告可能包含主机名、系统信息、登录记录、账号名、IP 地址、监听端口和安全配置。默认以 `600` 权限保存。不要将真实审计报告或 AI 提示词提交到公开仓库。

## 特性

- 只读检查：不主动修改系统配置或安装软件。
- 统一的 `PASS` / `WARN` / `FAIL` / `INFO` / `SKIP` 检查结果。
- 输出安全评分、问题详情、修复建议和 AI 加固提示词。
- 报告文件默认仅文件所有者可读（`umask 077`、权限 `600`）。
- 适用于 Ubuntu / Debian；其他发行版可能仅部分兼容。

## 要求

- Bash 4+
- Ubuntu / Debian（建议以 root 权限运行）
- 部分检查依赖系统已有工具，例如 `ss`、`systemctl`、`sysctl`、`dpkg`、`journalctl`、`findmnt`、`docker`。缺少工具时部分检查会跳过或提示。

## 使用

```bash
# 下载脚本后
sudo bash vps_audit.sh

# 指定报告输出目录
sudo bash vps_audit.sh /root/audit-reports
```

运行结束后，终端会显示 Markdown 报告和 AI 提示词文件的路径。报告仅保存在本机，不会自动上传。

## 运行前注意

1. 仅在你拥有或获准管理的服务器上运行。
2. 脚本会读取本机安全配置、登录日志、进程和监听端口等信息。
3. 检查结果是轻量级基线提示，不等同于完整渗透测试、合规审计或恶意软件取证。
4. 修复建议需要结合业务环境评估；尤其不要未经确认就关闭 SSH 密码登录、修改防火墙或禁用服务，以免造成远程锁定或业务中断。
5. 分享报告前先脱敏，并通过安全渠道传输。

## 目录结构

```text
vps-security-audit/
├── vps_audit.sh
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
├── .shellcheckrc
├── .github/workflows/ci.yml
└── tests/test_basic.sh
```

## 测试

```bash
bash -n vps_audit.sh
bash tests/test_basic.sh
```

CI 会在 push 和 pull request 时执行 Bash 语法检查、基础静态测试及 ShellCheck。

## 许可证

本项目采用 MIT License，详见 [LICENSE](LICENSE)。发布前请将许可证中的 `[Your Name]` 替换为版权持有人名称。
