#!/usr/bin/env bash
# =============================================================
# vps_audit.sh - VPS 安全审计脚本 (Ubuntu / Debian)
# 特点: 只读检查, 不修改系统配置; 结束后生成 Markdown 报告 + AI 提示词
# 扩展约定: 新检查使用唯一 ID, 通过 record() 统一记录 PASS/WARN/FAIL/INFO/SKIP
# 用法: sudo bash vps_audit.sh [报告输出目录]
#   默认输出到 sudo 调用者的家目录, 文件属主为该用户 (权限 600, 仅所有者可读);
#   直接以 root 登录运行时则输出到 /root。
# =============================================================
export LC_ALL=C
umask 077  # 报告默认仅文件所有者可读，避免泄露主机信息
SCRIPT_VERSION="1.1"   # 注意: 不能叫 VERSION, 会被 /etc/os-release 覆盖

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行: sudo bash $0"; exit 1; }
. /etc/os-release 2>/dev/null
case "${ID:-}" in
  ubuntu|debian) ;;
  *) echo "警告: 本脚本针对 Ubuntu/Debian, 当前系统 ${PRETTY_NAME:-未知}, 部分检查可能不准确" ;;
esac

HOST="$(hostname)"
HOST_FILE="$(printf '%s' "$HOST" | tr -cd 'A-Za-z0-9._-')"
[ -n "$HOST_FILE" ] || HOST_FILE="vps"
# 报告含主机、账号、网络和安全信息，默认仅所有者可读
REPORT_MODE=600
SSH_PORT=22
KRN_N=0
TS="$(date +%Y%m%d_%H%M%S)"
# 报告属主: 用 sudo 运行时归调用者所有 (否则只有 root 能读); 直接 root 登录则归 root
OWNER="root"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && id "$SUDO_USER" >/dev/null 2>&1; then
  OWNER="$SUDO_USER"
fi
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
OUT_DIR="${1:-${OWNER_HOME:-/root}}"
mkdir -p -- "$OUT_DIR" || { echo "无法创建报告目录: $OUT_DIR" >&2; exit 1; }
[ -d "$OUT_DIR" ] && [ -w "$OUT_DIR" ] || { echo "报告目录不可写: $OUT_DIR" >&2; exit 1; }
REPORT="$OUT_DIR/vps_audit_${HOST_FILE}_${TS}_$$.md"
PROMPT_FILE="$OUT_DIR/vps_audit_${HOST_FILE}_${TS}_$$_ai_prompt.txt"
REPORT_TMP="$(mktemp "$OUT_DIR/.vps_audit_report.XXXXXX")" || { echo "无法创建报告临时文件" >&2; exit 1; }
PROMPT_TMP="$(mktemp "$OUT_DIR/.vps_audit_prompt.XXXXXX")" || { rm -f -- "$REPORT_TMP"; echo "无法创建提示词临时文件" >&2; exit 1; }
trap 'rm -f -- "${REPORT_TMP:-}" "${PROMPT_TMP:-}"' EXIT

PASS=0; WARN=0; FAIL=0; SKIP=0; INFO=0
RESULTS=()   # 格式: STATUS|ID|标题|详情|修复建议（字段内容中的 | 会被 clean() 转义）

clean() { tr '\n' ' ' | sed 's/|/\//g; s/  */ /g'; }

# 扩展规范: 每个检查分配稳定且唯一的 ID; 每次执行必须记录一个状态。
# PASS=通过, WARN=需人工核实, FAIL=高风险, INFO=仅提供信息, SKIP=未执行/不适用。
record() { # status id title [detail] [fix]
  local s="$1" id="$2" t d f
  t="$(printf '%s' "$3" | clean)"
  d="$(printf '%s' "${4:-}" | clean)"
  f="$(printf '%s' "${5:-}" | clean)"
  case "$s" in
    PASS) PASS=$((PASS+1));;
    WARN) WARN=$((WARN+1));;
    FAIL) FAIL=$((FAIL+1));;
    SKIP) SKIP=$((SKIP+1));;
    INFO) INFO=$((INFO+1));;
    *) echo "内部错误: 未知检查状态 $s (ID=$id)" >&2; return 2;;
  esac
  RESULTS+=("$s|$id|$t|$d|$f")
  printf '[%-4s] %-10s %s\n' "$s" "$id" "$t"
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "=== VPS 安全审计开始 ($(date)) ==="

# ------------------------------------------------------------
# 1. 系统与更新
# ------------------------------------------------------------
KERNEL="$(uname -r)"
UPG_ALL=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
UPG_SEC=$(apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci security)
if [ "$UPG_SEC" -gt 0 ]; then
  record FAIL SYS-01 "有 $UPG_SEC 个安全更新未安装" "共 $UPG_ALL 个可更新包 (基于本地 apt 缓存)" "apt update && apt upgrade -y"
elif [ "$UPG_ALL" -gt 0 ]; then
  record WARN SYS-01 "有 $UPG_ALL 个普通更新未安装" "" "apt update && apt upgrade -y"
else
  record PASS SYS-01 "系统包已是最新 (基于本地缓存)"
fi

if [ -f /var/run/reboot-required ]; then
  record WARN SYS-02 "系统需要重启以应用更新 (内核/库)" "" "择机执行 reboot"
else
  record PASS SYS-02 "无待重启项"
fi

if dpkg -s unattended-upgrades >/dev/null 2>&1; then
  record PASS SYS-03 "已安装 unattended-upgrades (自动安全更新)"
else
  record WARN SYS-03 "未安装 unattended-upgrades" "" "apt install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
fi

TS_SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
if [ "$TS_SYNC" = "yes" ]; then
  record PASS SYS-04 "时间已同步 (NTP)"
else
  record WARN SYS-04 "时间未同步" "日志时间不准会影响取证" "timedatectl set-ntp true 或安装 chrony"
fi

# ------------------------------------------------------------
# 2. SSH 配置
# ------------------------------------------------------------
SSHD_T="$(sshd -T 2>/dev/null)"
sshv() { echo "$SSHD_T" | awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit }'; }

if [ -z "$SSHD_T" ]; then
  record WARN SSH-00 "无法读取 sshd 有效配置 (sshd -T 失败或未安装 sshd)"
else
  v="$(sshv permitrootlogin)"
  case "$v" in
    no) record PASS SSH-01 "禁止 root 直接登录" ;;
    prohibit-password|without-password) record WARN SSH-01 "root 允许密钥登录 ($v)" "建议使用普通用户 + sudo" "PermitRootLogin no" ;;
    *) record FAIL SSH-01 "允许 root 密码登录 (PermitRootLogin $v)" "" "PermitRootLogin no (先确认已有可 sudo 的普通用户)" ;;
  esac

  v="$(sshv passwordauthentication)"
  if [ "$v" = "no" ]; then record PASS SSH-02 "已禁用 SSH 密码登录"
  else record FAIL SSH-02 "SSH 允许密码登录" "易被暴力破解" "先配置好公钥并在新窗口测试成功后: PasswordAuthentication no"; fi

  v="$(sshv permitemptypasswords)"
  if [ "$v" = "yes" ]; then record FAIL SSH-03 "SSH 允许空密码" "" "PermitEmptyPasswords no"
  else record PASS SSH-03 "不允许空密码登录"; fi

  v="$(sshv kbdinteractiveauthentication)"
  if [ "$v" = "yes" ]; then record WARN SSH-04 "键盘交互认证已开启 (可能等同密码登录)" "" "KbdInteractiveAuthentication no"
  else record PASS SSH-04 "键盘交互认证已关闭"; fi

  v="$(sshv maxauthtries)"
  if [ -n "$v" ] && [ "$v" -gt 4 ] 2>/dev/null; then record WARN SSH-05 "MaxAuthTries=$v 偏大" "" "MaxAuthTries 3"
  else record PASS SSH-05 "MaxAuthTries=$v"; fi

  v="$(sshv x11forwarding)"
  if [ "$v" = "yes" ]; then record WARN SSH-06 "X11Forwarding 已开启" "" "X11Forwarding no"
  else record PASS SSH-06 "X11Forwarding 已关闭"; fi

  v="$(sshv port)"; SSH_PORT="${v:-22}"
  if [ "$v" = "22" ]; then record WARN SSH-07 "SSH 使用默认端口 22" "改端口不是真正的安全措施, 只能减少扫描噪音" "可选: 改为高位端口, 同时先在防火墙放行新端口"
  else record PASS SSH-07 "SSH 端口为 $v"; fi

  v="$(sshv clientaliveinterval)"
  if [ "${v:-0}" = "0" ]; then record WARN SSH-08 "未配置 ClientAliveInterval (空闲会话不会超时)" "" "ClientAliveInterval 300 / ClientAliveCountMax 2"
  else record PASS SSH-08 "已配置空闲超时 ($v 秒)"; fi

  v="$(sshv logingracetime)"
  if [ -n "$v" ] && [ "$v" -gt 60 ] 2>/dev/null; then record WARN SSH-09 "LoginGraceTime=$v 偏大" "" "LoginGraceTime 30"
  else record PASS SSH-09 "LoginGraceTime=$v"; fi

  v="$(sshv allowusers)$(sshv allowgroups)"
  if [ -z "$v" ]; then record WARN SSH-10 "未限制可登录用户 (AllowUsers/AllowGroups)" "" "AllowUsers <你的用户名>"
  else record PASS SSH-10 "已限制可登录用户"; fi
fi

# ------------------------------------------------------------
# 3. 账号与权限
# ------------------------------------------------------------
UID0="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)"
if [ -n "$UID0" ]; then record FAIL USR-01 "存在非 root 的 UID=0 账号" "$UID0" "userdel 或改 UID, 并排查是否被入侵"
else record PASS USR-01 "仅 root 的 UID 为 0"; fi

EMPTYPW="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)"
if [ -n "$EMPTYPW" ]; then record FAIL USR-02 "存在空密码账号" "$EMPTYPW" "passwd -l <用户> 或设置强密码"
else record PASS USR-02 "无空密码账号"; fi

NOPW="$(grep -rEh '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)"
if [ -n "$NOPW" ]; then record WARN USR-03 "sudo 配置了 NOPASSWD" "$NOPW" "非必要请取消 NOPASSWD (云厂商默认用户可能需要保留)"
else record PASS USR-03 "sudo 未配置 NOPASSWD"; fi

SHELL_USERS="$(awk -F: '$3>=1000 && $1!="nobody" && $7 !~ /(nologin|false)$/{print $1}' /etc/passwd | tr '\n' ' ')"
record PASS USR-04 "可登录的普通用户: ${SHELL_USERS:-无}" "请确认均为已知账号"

RAK=/root/.ssh/authorized_keys
if [ -s "$RAK" ]; then
  record WARN USR-05 "root 存在 authorized_keys ($(grep -cE '^(ssh|ecdsa)' $RAK) 把公钥)" "请确认均为自己的密钥" "审查 $RAK, 删除未知公钥"
else
  record PASS USR-05 "root 无 authorized_keys"
fi

PMD="$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs)"
if [ "${PMD:-99999}" -ge 99999 ] 2>/dev/null; then
  record WARN USR-06 "密码永不过期 (PASS_MAX_DAYS=${PMD:-未设置})" "若全部使用密钥登录, 优先级低" "按需设置 PASS_MAX_DAYS 180"
else
  record PASS USR-06 "PASS_MAX_DAYS=$PMD"
fi

# ------------------------------------------------------------
# 4. 防火墙与网络
# ------------------------------------------------------------
FW="无"
if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then FW="ufw"
elif have nft && nft list ruleset 2>/dev/null | grep -q 'hook input.*policy drop'; then FW="nftables"
elif have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then FW="iptables"
fi
if [ "$FW" = "无" ]; then
  record FAIL NET-01 "未检测到启用的主机防火墙" "" "apt install -y ufw; ufw default deny incoming; ufw allow <SSH端口>/tcp; ufw enable (先放行 SSH!)"
else
  record PASS NET-01 "防火墙已启用: $FW"
fi

PORT_TOOL=0; PORTS_TXT=""
if have ss; then
  PORT_TOOL=1
  # 去掉表头; 列: Netid State Recv-Q Send-Q Local Peer [Process]
  PORTS_TXT="$(ss -tulnp 2>/dev/null | awk 'NR>1')"
elif have netstat; then
  PORT_TOOL=1
  # 转成与 ss 相同的列顺序
  PORTS_TXT="$(netstat -tulnp 2>/dev/null | awk 'NR>2{print $1,"-","-","-",$4,$5}')"
fi
RISKY_PORTS=" 21 23 69 111 135 139 445 2049 2375 3306 3389 5432 5900 6379 9200 11211 27017 "
PUB_LIST=""; RISKY_FOUND=""
while read -r proto _ _ _ laddr _; do
  [ -z "$laddr" ] && continue
  port="${laddr##*:}"; addr="${laddr%:*}"
  case "$addr" in 127.*|"[::1]"|::1|*%lo) continue ;; esac
  PUB_LIST="$PUB_LIST ${proto}/${port}"
  case "$RISKY_PORTS" in *" $port "*) RISKY_FOUND="$RISKY_FOUND ${proto}/${port}" ;; esac
done <<< "$PORTS_TXT"
if [ "$PORT_TOOL" -eq 0 ]; then
  record WARN NET-02 "无法检查监听端口 (系统缺少 ss/netstat)" "" "apt install -y iproute2 后重新运行"
elif [ -n "$RISKY_FOUND" ]; then
  record FAIL NET-02 "高风险服务端口对外监听:$RISKY_FOUND" "数据库/缓存/Docker API 等不应暴露公网" "改为监听 127.0.0.1 或用防火墙限制来源 IP"
else
  record PASS NET-02 "未发现常见高风险端口对外监听"
fi
PUB_LIST="$(printf '%s\n' $PUB_LIST | sort -u | tr '\n' ' ')"   # 去重 (IPv4/IPv6 会重复)
[ "$PORT_TOOL" -eq 1 ] && record PASS NET-03 "对外监听端口清单: ${PUB_LIST:-无}" "请逐个确认是否必要"

# ------------------------------------------------------------
# 5. 入侵防护与暴力破解
# ------------------------------------------------------------
if systemctl is-active --quiet fail2ban 2>/dev/null; then record PASS IPS-01 "fail2ban 运行中"
elif systemctl is-active --quiet crowdsec 2>/dev/null; then record PASS IPS-01 "crowdsec 运行中"
else record WARN IPS-01 "未运行 fail2ban/crowdsec" "" "apt install -y fail2ban && systemctl enable --now fail2ban"; fi

if [ -f /var/log/auth.log ]; then
  FAILED_LOG="$(grep -aE 'Failed password|Invalid user' /var/log/auth.log /var/log/auth.log.1 2>/dev/null)"
else
  FAILED_LOG="$(journalctl -u ssh -u sshd --since '-7d' --no-pager 2>/dev/null | grep -E 'Failed password|Invalid user')"
fi
FAILED_N="$(printf '%s' "$FAILED_LOG" | grep -c .)"
TOP_IPS="$(printf '%s' "$FAILED_LOG" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s(%s次) ", $2, $1}')"
if [ "$FAILED_N" -gt 1000 ]; then
  record WARN IPS-02 "近期 SSH 失败登录 $FAILED_N 次 (暴力破解强烈)" "Top: $TOP_IPS" "禁用密码登录 + fail2ban"
else
  record PASS IPS-02 "近期 SSH 失败登录 $FAILED_N 次" "Top: ${TOP_IPS:-无}"
fi

if have auditctl && systemctl is-active --quiet auditd 2>/dev/null; then record PASS IPS-03 "auditd 运行中"
else record WARN IPS-03 "未运行 auditd (无系统调用/文件审计)" "" "apt install -y auditd"; fi

if [ -d /sys/module/apparmor ] && [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ]; then
  record PASS IPS-04 "AppArmor 已启用"
else
  record WARN IPS-04 "AppArmor 未启用" "" "apt install -y apparmor apparmor-utils (视内核/发行版而定)"
fi

# ------------------------------------------------------------
# 6. 内核参数
# ------------------------------------------------------------
chk_sysctl() { # key want [sev] [note]
  local k="$1" want="$2" sev="${3:-WARN}" note="${4:-}" cur id
  cur="$(sysctl -n "$k" 2>/dev/null)" || return
  KRN_N=$((KRN_N+1)); id="$(printf 'KRN-%02d' "$KRN_N")"
  if [ "$cur" = "$want" ]; then record PASS "$id" "$k = $cur"
  else record "$sev" "$id" "$k = $cur (建议 $want)" "$note" "写入 /etc/sysctl.d/99-hardening.conf: $k = $want, 然后 sysctl --system"; fi
}
chk_sysctl net.ipv4.tcp_syncookies 1
chk_sysctl net.ipv4.conf.all.rp_filter 1
chk_sysctl net.ipv4.conf.all.accept_redirects 0
chk_sysctl net.ipv4.conf.all.send_redirects 0
chk_sysctl net.ipv4.conf.all.accept_source_route 0
chk_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
chk_sysctl net.ipv4.conf.all.log_martians 1
chk_sysctl kernel.randomize_va_space 2 FAIL
chk_sysctl kernel.kptr_restrict 2
chk_sysctl kernel.dmesg_restrict 1
chk_sysctl fs.protected_hardlinks 1
chk_sysctl fs.protected_symlinks 1
chk_sysctl fs.suid_dumpable 0
chk_sysctl kernel.yama.ptrace_scope 1
chk_sysctl net.ipv4.ip_forward 0 WARN "若使用 Docker/VPN/路由转发可忽略"

# ------------------------------------------------------------
# 7. 文件权限与可疑文件
# ------------------------------------------------------------
check_perm() { # file maxperm id
  local f="$1" max="$2" id="$3" p
  [ -e "$f" ] || return
  p="$(stat -c %a "$f")"
  if (( (8#$p & ~8#$max) != 0 )); then record FAIL "$id" "$f 权限过宽 ($p)" "建议 <= $max" "chmod $max $f"
  else record PASS "$id" "$f 权限正常 ($p)"; fi
}
check_perm /etc/passwd 644 FIL-01
check_perm /etc/shadow 640 FIL-02
check_perm /etc/gshadow 640 FIL-03
check_perm /etc/ssh/sshd_config 644 FIL-04
check_perm /root 700 FIL-05
check_perm /etc/crontab 644 FIL-06

SUID_KNOWN='/(su|sudo|passwd|mount|umount|chsh|chfn|newgrp|gpasswd|pkexec|ping|ping6|fusermount3?|ssh-keysign|dbus-daemon-launch-helper|polkit-agent-helper-1|unix_chkpwd|chage|expiry|at|crontab|mount\.nfs|vmware-user-suid-wrapper|snap-confine|sudoedit|write|wall|ssh-agent|bsd-write|dotlockfile|mlocate|plocate|ntfs-3g|fusermount|pam_timestamp_check|Xorg\.wrap)$'
# 单次遍历同时收集全局可写文件和 SUID 文件，减少重复扫描。
FILE_MODE_SCAN="$(timeout 30 find / -xdev \
  \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o \
  -type f \( \
    \( -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/var/lib/docker/*' -printf 'WW %p\n' \) -o \
    \( -perm -4000 -printf 'SUID %p\n' \) \
  \) 2>/dev/null)"
FILE_MODE_RC=$?
WW="$(printf '%s\n' "$FILE_MODE_SCAN" | sed -n 's/^WW //p' | head -15)"
SUID_ALL="$(printf '%s\n' "$FILE_MODE_SCAN" | sed -n 's/^SUID //p')"
SUID_ODD="$(printf '%s\n' "$SUID_ALL" | grep -Ev "$SUID_KNOWN" | head -15)"
if [ "$FILE_MODE_RC" -eq 124 ]; then
  record WARN FIL-07 "全局可写文件扫描超时, 结果不完整" "扫描在 30 秒后终止" "可在低负载时段重新运行"
  record WARN FIL-08 "SUID 文件扫描超时, 结果不完整" "扫描在 30 秒后终止" "可在低负载时段重新运行"
elif [ "$FILE_MODE_RC" -ne 0 ]; then
  record WARN FIL-07 "全局可写文件扫描执行失败" "find 退出码: $FILE_MODE_RC" "检查文件系统访问权限"
  record WARN FIL-08 "SUID 文件扫描执行失败" "find 退出码: $FILE_MODE_RC" "检查文件系统访问权限"
else
  if [ -n "$WW" ]; then record WARN FIL-07 "存在全局可写文件" "$WW" "逐项确认用途; 不要直接批量修改权限"
  else record PASS FIL-07 "未发现全局可写文件"; fi
  if [ -n "$SUID_ODD" ]; then record WARN FIL-08 "发现非常见 SUID 程序" "$SUID_ODD" "确认来源, 不需要则 chmod u-s <文件>"
  else record PASS FIL-08 "未发现非常见 SUID 程序"; fi
fi
TMPOPT="$(findmnt -no OPTIONS /tmp 2>/dev/null)"
if [ -z "$TMPOPT" ]; then record WARN FIL-09 "/tmp 未单独挂载" "" "可选: tmpfs 挂载 /tmp 并加 noexec,nosuid,nodev"
elif echo "$TMPOPT" | grep -q noexec; then record PASS FIL-09 "/tmp 已 noexec"
else record WARN FIL-09 "/tmp 未设置 noexec" "" "mount 选项加 noexec,nosuid,nodev"; fi

for d in $(df -P -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{gsub("%","",$5); if ($5+0>=90) print $6"("$5"%)"}'); do
  record WARN FIL-10 "磁盘占用过高: $d" "磁盘写满会导致日志丢失/服务异常" "清理日志与旧包"
done

# ------------------------------------------------------------
# 8. 服务与计划任务
# ------------------------------------------------------------
BAD_SVC=""
for s in telnet telnetd rsh-server vsftpd proftpd tftpd-hpa nfs-server rpcbind avahi-daemon cups snmpd smbd isc-dhcp-server; do
  systemctl is-active --quiet "$s" 2>/dev/null && BAD_SVC="$BAD_SVC $s"
done
if [ -n "$BAD_SVC" ]; then record WARN SVC-01 "运行着通常不需要的服务:$BAD_SVC" "" "systemctl disable --now <服务名>"
else record PASS SVC-01 "未发现常见不必要/明文协议服务"; fi

SUS_CRON="$(grep -rEl '(curl|wget)[^#]*[|][[:space:]]*(sudo[[:space:]]+)?(/bin/)?(ba)?sh' /etc/cron* /var/spool/cron 2>/dev/null)"
if [ -n "$SUS_CRON" ]; then record FAIL SVC-02 "计划任务中有 下载并直接执行 的可疑命令" "$SUS_CRON" "立即人工审查, 可能已被入侵"
else record PASS SVC-02 "计划任务中未发现 curl|sh 类可疑命令"; fi

# ------------------------------------------------------------
# 9. 入侵迹象 (轻量级)
# ------------------------------------------------------------
EXE_LIST="$(ls -l /proc/[0-9]*/exe 2>/dev/null)"
SUS_PROC="$(printf '%s\n' "$EXE_LIST" | grep -E ' /tmp/| /dev/shm/| /var/tmp/' | head -10)"
DEL_PROC="$(printf '%s\n' "$EXE_LIST" | grep -E '\(deleted\)|memfd:' | head -10)"
if [ -n "$SUS_PROC" ]; then record FAIL IOC-01 "有进程从 /tmp、/dev/shm 运行" "$SUS_PROC" "立即排查 (常见于挖矿木马/后门)"
else record PASS IOC-01 "未发现从临时目录运行的进程"; fi
if [ -n "$DEL_PROC" ]; then record WARN IOC-04 "有进程的可执行文件已被删除或来自内存(memfd)" "升级软件后未重启服务时很常见, 也可能是无文件木马: $DEL_PROC" "安装 needrestart 并重启相关服务; 重启后仍存在再人工排查"
else record PASS IOC-04 "无已删除/memfd 可执行文件的进程"; fi

TOPCPU="$(ps -eo pcpu,comm --sort=-pcpu 2>/dev/null | awk 'NR==2{print $1" "$2}')"
record PASS IOC-02 "CPU 占用最高进程: $TOPCPU" "长期占满 CPU 且不认识的进程需排查"

RECENT_KEYS="$(find /root /home -name authorized_keys -mtime -7 2>/dev/null)"
if [ -n "$RECENT_KEYS" ]; then record WARN IOC-03 "近 7 天内 authorized_keys 被修改" "$RECENT_KEYS" "确认是否为自己操作"
else record PASS IOC-03 "近 7 天 authorized_keys 无变动"; fi

LAST_LOGINS="$(last -n 8 -a 2>/dev/null | head -8)"

# ------------------------------------------------------------
# 10. 深度入侵检测 (只读; 发现不等于确认入侵)
# ------------------------------------------------------------
# 检查持久化入口: systemd、cron、启动脚本及 shell 初始化文件。
PERSIST_FILES=""
# 只匹配“执行临时目录程序/下载后交给 shell 执行”等高风险模式，避免把 mktemp 等正常临时文件操作当成后门。
PERSIST_RE='(Exec(Start|StartPre|StartPost)=.*(/tmp/|/dev/shm/|/var/tmp/)|(^|[[:space:];|])(bash|sh|dash|python[0-9.]*|perl)[[:space:]].*(/tmp/|/dev/shm/|/var/tmp/)|(^|[[:space:]])exec[[:space:]]+(/tmp/|/dev/shm/|/var/tmp/)[^[:space:]]+|curl[^|]*[|][[:space:]]*(sudo[[:space:]]+)?(/bin/)?(ba)?sh|wget[^|]*[|][[:space:]]*(sudo[[:space:]]+)?(/bin/)?(ba)?sh)'
for d in /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/init.d /etc/profile.d; do
  [ -e "$d" ] || continue
  hits="$(grep -RInIE "$PERSIST_RE" "$d" 2>/dev/null | sed -n '1,20p')"
  [ -n "$hits" ] && PERSIST_FILES="${PERSIST_FILES}${hits}"$'\n'
done
for f in /etc/rc.local /etc/bash.bashrc /etc/profile; do
  [ -f "$f" ] || continue
  hits="$(grep -nE "$PERSIST_RE" "$f" 2>/dev/null | sed -n '1,10p')"
  [ -n "$hits" ] && PERSIST_FILES="${PERSIST_FILES}${f}:${hits}"$'\n'
done
if [ -n "$PERSIST_FILES" ]; then
  record WARN IOC-05 "持久化配置中发现临时目录或下载执行特征" "$(printf '%s\n' "$PERSIST_FILES" | sort -u | head -15 | tr '\n' ' ' | cut -c1-1200)" "逐项检查对应配置及其执行目标; 不要直接删除未知任务"
else
  record PASS IOC-05 "未发现明显可疑的持久化配置特征"
fi

# 检查所有常见用户目录中的 SSH 授权密钥及近期变更。
KEY_FILES="$(find /root /home -xdev -type f -name authorized_keys -print 2>/dev/null)"
KEY_RECENT="$(find /root /home -xdev -type f -name authorized_keys -mtime -7 -print 2>/dev/null)"
KEY_BADPERM=""
while IFS= read -r k; do
  [ -n "$k" ] || continue
  mode="$(stat -c '%a' "$k" 2>/dev/null)"
  [ -n "$mode" ] && (( (8#$mode & 0022) != 0 )) && KEY_BADPERM="$KEY_BADPERM $k($mode)"
done <<< "$KEY_FILES"
if [ -n "$KEY_RECENT" ] || [ -n "$KEY_BADPERM" ]; then
  record WARN IOC-06 "SSH 授权密钥近期变更或权限过宽" "近期变更: ${KEY_RECENT:-无}; 权限异常: ${KEY_BADPERM:-无}" "核对每把公钥指纹与操作者; 未确认前不要覆盖 authorized_keys"
else
  record PASS IOC-06 "未发现近期 SSH 授权密钥变更或明显权限异常"
fi

# 检查异常登录账号: 非 root 的 UID 0 已在 USR-01 检查; 此处列出可交互账号及 UID。
LOGIN_ACCOUNTS="$(awk -F: '$3>=1000 && $1!="nobody" && $7 !~ /(nologin|false)$/ {print $1 ":uid=" $3 ":home=" $6}' /etc/passwd 2>/dev/null)"
if [ -n "$LOGIN_ACCOUNTS" ]; then
  record INFO IOC-07 "可交互普通账号清单 (需管理员核实归属)" "$(printf '%s' "$LOGIN_ACCOUNTS" | tr '\n' '; ')" "确认账号归属、创建原因及 sudo 权限; 未确认前不要删除账号"
else
  record PASS IOC-07 "未发现 UID>=1000 的可交互普通账号"
fi

# 检查 systemd 单元中引用临时目录、可写目录或下载执行器的配置。
SYS_UNIT_HITS=""
for d in /etc/systemd/system /usr/local/lib/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
  [ -d "$d" ] || continue
  h="$(grep -RInE 'Exec(Start|StartPre|StartPost)=.*(/tmp/|/dev/shm/|/var/tmp/)|Exec(Start|StartPre|StartPost)=.*(curl|wget).*(sh|bash)' "$d" 2>/dev/null | head -20)"
  [ -n "$h" ] && SYS_UNIT_HITS="${SYS_UNIT_HITS}${h}"$'\n'
done
if [ -n "$SYS_UNIT_HITS" ]; then
  record WARN IOC-08 "systemd 单元包含高风险执行路径或下载执行命令" "$(printf '%s' "$SYS_UNIT_HITS" | tr '\n' '; ' | cut -c1-700)" "检查单元文件、启用状态、文件属主及目标程序哈希; 先留存证据"
else
  record PASS IOC-08 "未发现明显可疑的 systemd 执行配置"
fi

# 检查包管理器记录的已安装文件校验差异; 配置文件差异可能是管理员正常修改。
if have dpkg; then
  DPKG_VERIFY="$(timeout 45 dpkg -V 2>/dev/null)"
  DPKG_RC=$?
  if [ "$DPKG_RC" -eq 124 ]; then
    record WARN IOC-09 "dpkg 文件校验超时, 结果不完整" "检查在 45 秒后终止" "可在低负载时段重新运行并检查包文件"
  elif [ "$DPKG_RC" -ne 0 ]; then
    record WARN IOC-09 "dpkg 文件校验执行失败" "退出码: $DPKG_RC" "检查 dpkg 状态; 不能将执行失败视为校验通过"
  else
    DPKG_RELEVANT="$(printf '%s\n' "$DPKG_VERIFY" | grep -Ev '(^missing )?/usr/share/(doc|man|lintian|locale|info)/|(^missing )?/var/lib/apt/lists/')"
    if [ -n "$DPKG_RELEVANT" ]; then
      record WARN IOC-09 "dpkg 文件校验发现需核实的差异" "$(printf '%s\n' "$DPKG_RELEVANT" | head -30 | tr '\n' '; ' | cut -c1-900)" "优先核实可执行文件、共享库和系统配置; 文档缺失通常不代表入侵"
    elif [ -n "$DPKG_VERIFY" ]; then
      record INFO IOC-09 "dpkg 校验差异仅涉及常见文档/本地化文件" "未发现过滤范围外的校验差异" "如曾主动精简系统文档, 此结果通常属于预期"
    else
      record PASS IOC-09 "dpkg 未报告已安装软件文件校验差异"
    fi
  fi
else
  record SKIP IOC-09 "缺少 dpkg, 跳过软件文件完整性检查" "该项目未完成检查, 不能视为通过"
fi

# 检查异常 Linux capabilities; 输出由管理员安装的软件也可能合法使用 capabilities。
if have getcap; then
  CAP_RAW="$(timeout 30 getcap -r / 2>/dev/null)"
  CAP_RC=$?
  CAP_FILES="$(printf '%s\n' "$CAP_RAW" | grep -vE '^(/usr/bin/(ping|traceroute6?|mtr|arping)|/usr/sbin/(ping|tcpdump)|.*/gstreamer-1.0/gst-ptp-helper) ' | head -20)"
  if [ "$CAP_RC" -eq 124 ]; then
    record WARN IOC-10 "Capabilities 扫描超时, 结果不完整" "扫描在 30 秒后终止" "可在低负载时段重新运行"
  elif [ "$CAP_RC" -ne 0 ]; then
    record WARN IOC-10 "Capabilities 扫描执行失败" "getcap 退出码: $CAP_RC" "检查 libcap 工具及文件系统访问权限"
  elif [ -n "$CAP_FILES" ]; then
    record WARN IOC-10 "发现需人工核实的文件 capabilities" "$(printf '%s' "$CAP_FILES" | tr '\n' '; ' | cut -c1-900)" "核对文件来源、包归属及 capabilities 是否必要; 不要批量清除"
  else
    record PASS IOC-10 "未发现明显异常的文件 capabilities"
  fi
else
  record SKIP IOC-10 "未安装 getcap, 跳过文件 capabilities 检查" "该项目未完成检查, 不能视为通过" "可选安装 libcap2-bin 后重新审计"
fi

# 汇总当前已建立连接, 仅作调查线索; 外连本身不代表恶意。
if have ss; then
  ESTAB="$(ss -H -tunap state established 2>/dev/null | head -25)"
  if [ -n "$ESTAB" ]; then
    record PASS IOC-11 "已建立网络连接清单已采集" "$(printf '%s' "$ESTAB" | tr '\n' '; ' | cut -c1-1100)" "核对未知进程、远端地址和业务时段; 对可疑连接结合进程路径与日志调查"
  else
    record PASS IOC-11 "当前未发现已建立的 TCP/UDP 会话"
  fi
else
  record WARN IOC-11 "缺少 ss, 跳过已建立连接检查"
fi

# 可选调用已安装的 rootkit 检测工具; 不自动安装, 不把工具缺失判为入侵。
if have rkhunter; then
  RKH_RAW="$(timeout 60 rkhunter --check --sk --nocolors 2>&1)"
  RKH_RC=$?
  RKH_OUT="$(printf '%s\n' "$RKH_RAW" | grep -Ei 'Warning:|Possible|Found' | head -25)"
  if [ "$RKH_RC" -eq 124 ]; then
    record WARN IOC-12 "rkhunter 扫描超时, 结果不完整" "扫描在 60 秒后终止" "检查 /var/log/rkhunter.log 并在低负载时段重试"
  elif [ -n "$RKH_OUT" ]; then
    record WARN IOC-12 "rkhunter 报告需核实的项目" "$(printf '%s' "$RKH_OUT" | tr '\n' '; ' | cut -c1-1000)" "逐项复核 rkhunter 日志; 误报常见, 不要仅凭单条告警判定入侵"
  elif [ "$RKH_RC" -ne 0 ]; then
    record WARN IOC-12 "rkhunter 执行失败" "退出码: $RKH_RC; $(printf '%s' "$RKH_RAW" | tail -5 | tr '\n' '; ')" "检查工具配置和日志; 不能将执行失败视为安全通过"
  else
    record PASS IOC-12 "rkhunter 扫描完成, 未匹配到告警摘要"
  fi
elif have chkrootkit; then
  CRK_RAW="$(timeout 60 chkrootkit 2>&1)"
  CRK_RC=$?
  CRK_OUT="$(printf '%s\n' "$CRK_RAW" | grep -Ei 'INFECTED|warning|suspicious' | head -25)"
  if [ "$CRK_RC" -eq 124 ]; then
    record WARN IOC-12 "chkrootkit 扫描超时, 结果不完整" "扫描在 60 秒后终止" "在低负载时段重新运行"
  elif [ -n "$CRK_OUT" ]; then
    record WARN IOC-12 "chkrootkit 报告需核实的项目" "$(printf '%s' "$CRK_OUT" | tr '\n' '; ' | cut -c1-1000)" "逐项复核原始输出与文件来源; 不要仅凭单条告警判定入侵"
  elif [ "$CRK_RC" -ne 0 ]; then
    record WARN IOC-12 "chkrootkit 执行失败" "退出码: $CRK_RC" "检查工具输出; 不能将执行失败视为安全通过"
  else
    record PASS IOC-12 "chkrootkit 扫描完成, 未匹配到告警摘要"
  fi
else
  record SKIP IOC-12 "未安装 rkhunter/chkrootkit, 跳过可选 rootkit 扫描" "该项目未完成检查, 不能视为通过" "如需使用, 请先从可信软件源安装并单独审查工具配置"
fi

# ------------------------------------------------------------
# 11. Docker
# ------------------------------------------------------------
if have docker && docker info >/dev/null 2>&1; then
  PRIV="$(docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null | grep 'privileged=true')"
  if [ -n "$PRIV" ]; then record WARN DKR-01 "存在 privileged 容器" "$PRIV" "去掉 --privileged, 使用最小 capabilities"
  else record PASS DKR-01 "无 privileged 容器"; fi
  record WARN DKR-02 "Docker 会绕过 ufw 直接改 iptables" "-p 发布的端口可能对公网开放" "发布端口写成 127.0.0.1:主机端口:容器端口, 或使用 DOCKER-USER 链"
fi

# ============================================================
# 生成报告
# ============================================================
TOTAL=$((PASS+WARN+FAIL+INFO))  # SKIP 不计入已执行检查总数
SCORED_TOTAL=$((PASS+WARN+FAIL))
# 归一化评分: PASS=100 分, WARN=50 分, FAIL=0 分; INFO/SKIP 不参与评分
if [ "$SCORED_TOTAL" -gt 0 ]; then SCORE=$(((PASS*100 + WARN*50) / SCORED_TOTAL)); else SCORE=100; fi
if [ "$SCORE" -ge 85 ]; then GRADE="良好"; elif [ "$SCORE" -ge 60 ]; then GRADE="一般"; else GRADE="较差"; fi

fmt_items() { # 按状态输出
  local want="$1" line s id t d f
  for line in "${RESULTS[@]}"; do
    IFS='|' read -r s id t d f <<< "$line"
    [ "$s" = "$want" ] || continue
    echo "- **[$id] $t**"
    [ -n "$d" ] && echo "  - 详情: $d"
    [ -n "$f" ] && echo "  - 建议: \`$f\`"
  done
}

ISSUE_LIST=""
for line in "${RESULTS[@]}"; do
  IFS='|' read -r s id t d f <<< "$line"
  [[ "$s" = "PASS" || "$s" = "SKIP" || "$s" = "INFO" ]] && continue
  ISSUE_LIST="${ISSUE_LIST}- [$s][$id] $t${f:+ => 建议: $f}"$'\n'
done
[ -z "$ISSUE_LIST" ] && ISSUE_LIST="- (本次审计未发现问题)"$'\n'

AI_PROMPT="你是一名资深 Linux 安全工程师。请根据下面的审计结果, 为我的 VPS 生成一个**加固脚本**。

【环境】
- 系统: ${PRETTY_NAME:-Ubuntu/Debian} (内核 $KERNEL)
- SSH 当前端口: $SSH_PORT
- 防火墙现状: $FW
- 是否使用 Docker: $(have docker && echo 是 || echo 否)

【审计发现的问题】
${ISSUE_LIST}
【脚本要求】
1. 输出一个完整的 Bash 脚本 (hardening.sh), 仅适用于 Ubuntu/Debian, 使用 apt。
2. 必须以 root 运行, 开头检查 root 和系统类型。
3. 幂等: 重复执行不会重复追加配置、不会报错。
4. 修改任何配置文件前, 先备份到 /root/hardening_backup_<时间戳>/, 并生成 rollback.sh 用于一键回滚。
5. 支持 --dry-run (只打印将要执行的操作) 和 --yes (跳过确认) 参数, 默认每个模块执行前询问确认。
6. **防锁死 (最重要)**:
   - 修改 SSH 前, 先在防火墙放行当前 SSH 端口 ($SSH_PORT), 再启用防火墙。
   - 只有在检测到当前用户存在有效 authorized_keys 公钥时, 才允许禁用 SSH 密码登录, 并提示我在新终端测试成功后再继续。
   - 修改 sshd_config 后必须先执行 sshd -t 校验, 通过后才 reload (不是 restart), 失败则自动回滚。
   - 不要擅自更改 SSH 端口, 除非我在脚本顶部变量中明确设置。
7. 模块化: SSH 加固 / 防火墙(ufw) / fail2ban / 内核参数(sysctl.d) / 自动安全更新 / 文件权限 / 禁用不必要服务 / auditd。每个模块独立函数。
8. 脚本顶部集中放置可配置变量 (SSH_PORT、ADMIN_USER、额外放行端口、是否保留 ip_forward 等)。
9. 若使用 Docker, 不要破坏现有容器网络, 并提醒 Docker 绕过 ufw 的问题。
10. 不要自动重启服务器; 需要重启时仅在结尾提示。
11. 带彩色日志, 每步输出 做了什么/为什么, 结尾输出变更摘要; 同时写入 /var/log/hardening.log。
12. 仅用于加固自己拥有的服务器, 不得包含任何扫描、攻击或绕过授权的内容。
13. 先用简短文字说明整体方案和风险点, 再给出完整脚本, 最后给出 运行方式 和 验证方法 (例如重新运行审计脚本对比评分)。"

{
cat <<EOF
# VPS 安全审计报告

| 项目 | 内容 |
|---|---|
| 主机名 | $HOST |
| 系统 | ${PRETTY_NAME:-未知} |
| 内核 | $KERNEL |
| 审计时间 | $(date '+%F %T %Z') |
| 运行时长 | $(uptime -p 2>/dev/null) |
| 脚本版本 | v$SCRIPT_VERSION (只读审计, 未修改系统) |

## 1. 总览

- **安全评分: $SCORE / 100 ($GRADE)**
- 🔴 FAIL: $FAIL　🟡 WARN: $WARN　🟢 PASS: $PASS　🔵 INFO: $INFO　⚪ SKIP: $SKIP　(已执行 $TOTAL 项)
- 评分规则: PASS=100 分、WARN=50 分、FAIL=0 分; INFO/SKIP 不参与评分

## 2. 严重问题 (优先处理)

$(fmt_items FAIL)

## 3. 警告项

$(fmt_items WARN)

## 4. 通过项

$(fmt_items PASS | grep '^- \*\*' )

## 5. 未执行/跳过项

$(fmt_items SKIP | grep '^- \*\*' )

## 6. 信息项

$(fmt_items INFO | grep '^- \*\*' )

## 7. 参考信息

### 监听端口
\`\`\`
$PORTS_TXT
\`\`\`

### 最近登录记录
\`\`\`
$LAST_LOGINS
\`\`\`

## 8. 优化建议 (按优先级)

**P0 立即处理**
1. 处理第 2 节所有 FAIL 项; 若出现 IOC (入侵迹象) 类 FAIL, 先隔离排查再加固。
2. 使用 SSH 密钥登录, 禁用密码登录和 root 登录 (**先在新窗口验证密钥可用, 避免锁死自己**)。
3. 启用防火墙, 只开放必要端口 (SSH / 80 / 443 等), 数据库与缓存只监听 127.0.0.1。

**P1 本周内**
4. 安装并启用 fail2ban (或 crowdsec) 防暴力破解。
5. 开启 unattended-upgrades 自动安全更新, 定期重启应用内核更新。
6. 应用内核加固参数 (sysctl.d), 修复关键文件权限。

**P2 持续改进**
7. 部署 auditd、AppArmor, 日志集中外发 (防止被入侵后日志被删)。
8. 定期快照/异地备份, 并演练恢复。
9. 定期重跑本脚本, 对比评分变化; 可配合 Lynis 做更深入的基线检查。

## 9. AI 提示词: 生成 VPS 加固脚本

> 用法: 复制下面整个代码块, 发给 AI (Claude / ChatGPT 等)。
> 发送前请检查内容, 如含有不想外传的信息 (用户名、路径等) 请先删除。
> **AI 生成的脚本务必先 --dry-run, 并保留一个已登录的 SSH 窗口再执行。**

\`\`\`text
$AI_PROMPT
\`\`\`

---
*报告含服务器敏感信息, 请勿公开分享。*
EOF
} > "$REPORT_TMP"

printf '%s\n' "$AI_PROMPT" > "$PROMPT_TMP"
chmod "$REPORT_MODE" "$REPORT_TMP" "$PROMPT_TMP"
chown "$OWNER":"$(id -gn "$OWNER")" "$REPORT_TMP" "$PROMPT_TMP" 2>/dev/null
mv -f -- "$REPORT_TMP" "$REPORT" || { echo "写入报告失败: $REPORT" >&2; exit 1; }
mv -f -- "$PROMPT_TMP" "$PROMPT_FILE" || { echo "写入提示词失败: $PROMPT_FILE" >&2; exit 1; }

echo
echo "=== 审计完成: 评分 $SCORE/100 ($GRADE)  FAIL=$FAIL WARN=$WARN PASS=$PASS INFO=$INFO SKIP=$SKIP ==="
echo "报告:     $REPORT"
echo "AI 提示词: $PROMPT_FILE"
