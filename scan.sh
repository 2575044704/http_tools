#!/usr/bin/env bash

# --- 配置 ---
TARGET_PORT="8188"
SCAN_RATE="1000000"         # 扫描速率 (packets/sec)
WAIT_DURATION="10m"       # masscan 发送完包后等待响应的时间 (例如: 30s, 10m, 1h)
EXCLUDE_FILE="exclude_ips.txt"
OUTPUT_FILE="results_${TARGET_PORT}.json"
LOG_FILE="masscan_script.log" # 脚本执行日志

# 定义 SUDO_CMD 变量，根据是否为 root 用户
SUDO_CMD=""
if [[ $EUID -ne 0 ]]; then
    SUDO_CMD="sudo"
fi

# --- 函数 ---

# 日志记录函数
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# 检查并安装依赖 (libpcap) 和 masscan
install_masscan_and_deps() {
    # 检查并安装 libpcap 开发包
    log_message "检查/安装 libpcap 开发包 (masscan 依赖)..."
    if command -v apt-get &> /dev/null; then
        if ! dpkg -s libpcap-dev &> /dev/null; then
            log_message "使用 apt-get 安装 libpcap-dev..."
            $SUDO_CMD apt-get update || { log_message "apt-get update 失败"; exit 1; }
            $SUDO_CMD apt-get install -y libpcap-dev || { log_message "apt-get install libpcap-dev 失败"; exit 1; }
            log_message "libpcap-dev 安装成功。"
        else
            log_message "libpcap-dev 已安装。"
        fi
    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        local PKG_CMD
        if command -v yum &> /dev/null; then PKG_CMD="yum"; else PKG_CMD="dnf"; fi
        if ! rpm -q libpcap-devel &> /dev/null; then
            log_message "使用 $PKG_CMD 安装 libpcap-devel..."
            if [[ "$PKG_CMD" == "yum" ]] && ! rpm -q epel-release &>/dev/null; then
                 $SUDO_CMD $PKG_CMD install -y epel-release || { log_message "$PKG_CMD install epel-release 失败"; exit 1; }
            elif [[ "$PKG_CMD" == "dnf" ]] && ! rpm -q epel-release &>/dev/null; then
                 $SUDO_CMD $PKG_CMD install -y epel-release --enablerepo=extras || \
                 $SUDO_CMD $PKG_CMD install -y epel-release || \
                 log_message "警告: $PKG_CMD install epel-release 可能失败，但继续尝试安装 libpcap-devel。"
            fi
            $SUDO_CMD $PKG_CMD install -y libpcap-devel || { log_message "$PKG_CMD install libpcap-devel 失败"; exit 1; }
            log_message "libpcap-devel 安装成功。"
        else
            log_message "libpcap-devel 已安装。"
        fi
    else
        log_message "警告: 未知的包管理器。请确保 libpcap-dev 或 libpcap-devel 已手动安装。"
    fi

    # 检查并安装 masscan
    if command -v masscan &> /dev/null; then
        log_message "masscan 已安装: $(masscan --version 2>&1 | head -n 1)"
        return 0
    fi

    log_message "masscan 未找到。正在尝试安装..."
    if command -v apt-get &> /dev/null; then
        log_message "使用 apt-get 安装 masscan..."
        $SUDO_CMD apt-get install -y masscan || { log_message "apt-get install masscan 失败"; exit 1; }
    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        local PKG_CMD
        if command -v yum &> /dev/null; then PKG_CMD="yum"; else PKG_CMD="dnf"; fi
        log_message "使用 $PKG_CMD 安装 masscan..."
        $SUDO_CMD $PKG_CMD install -y masscan || { log_message "$PKG_CMD install masscan 失败"; exit 1; }
    else
        log_message "错误: 未知的包管理器。请手动安装 masscan。"
        log_message "您可以从 https://github.com/robertdavidgraham/masscan 获取源码并编译 (确保 libpcap-dev/libpcap-devel 已安装)。"
        exit 1
    fi

    if command -v masscan &> /dev/null; then
        log_message "masscan 安装成功: $(masscan --version 2>&1 | head -n 1)"
    else
        log_message "错误: masscan 安装失败。"
        exit 1
    fi
}

# 生成排除 IP 列表文件 (与之前相同)
generate_exclude_list() {
    log_message "正在生成排除 IP 列表文件: $EXCLUDE_FILE"
    cat > "$EXCLUDE_FILE" << EOF
# --- 特殊用途 IP 地址排除列表 ---

# RFC1918 - 私有地址
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# RFC5735 - 特殊用途地址块
0.0.0.0/8             # "This" Network
127.0.0.0/8           # Loopback
169.254.0.0/16        # Link-Local

# RFC5737 - 文档和示例地址 (TEST-NET)
192.0.2.0/24          # TEST-NET-1
198.51.100.0/24       # TEST-NET-2
203.0.113.0/24        # TEST-NET-3

# RFC6598 - Carrier-Grade NAT 共享地址空间
100.64.0.0/10

# IANA 保留 - IETF Protocol Assignments
192.0.0.0/24

# RFC2544 - Benchmarking Methodology for Network Interconnect Devices
198.18.0.0/15

# 多播地址 (Class D)
224.0.0.0/4

# 保留供将来使用 (Class E)
240.0.0.0/4

# --- 其他建议排除 ---
# 您的公共IP (避免扫描自己)
# 例如: YOUR_PUBLIC_IP_HERE (请取消注释并替换)

# 已知不应打扰的大型云服务商或CDN的某些核心段 (可选，需要自行调研)
# 例如:
# 1.1.1.1 # Cloudflare DNS
# 8.8.8.8 # Google DNS
# 8.8.4.4 # Google DNS
EOF
    log_message "$EXCLUDE_FILE 已生成。"
    log_message "重要提示: 请检查并根据需要编辑 '$EXCLUDE_FILE'，特别是添加您自己的公网 IP。"
    log_message "您可能还需要从 Team Cymru (https://www.team-cymru.org/Services/Bogons/) 等来源获取最新的 Bogon IP 列表并添加到排除文件中。"
}


# 执行 masscan 扫描
run_masscan() {
    log_message "准备执行 masscan 扫描..."
    log_message "目标端口: $TARGET_PORT"
    log_message "扫描速率: $SCAN_RATE packets/sec"
    log_message "等待时间: $WAIT_DURATION" # 新增日志
    log_message "排除文件: $EXCLUDE_FILE"
    log_message "输出文件: $OUTPUT_FILE"

    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 警告 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "您即将使用 masscan 扫描整个互联网 (0.0.0.0/0) 的端口 $TARGET_PORT。"
    echo "这可能违反您所在地区、ISP或目标网络的服务条款或法律。"
    echo "高速扫描可能会导致您的 IP 被封禁或被视为恶意行为。"
    echo "当前设置的扫描速率为 $SCAN_RATE pps。"
    echo "发送完所有包后将等待 $WAIT_DURATION 以接收响应。" # 新增警告信息
    echo "排除列表 '$EXCLUDE_FILE' 将被使用。"
    echo "结果将保存在 '$OUTPUT_FILE'。"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ""

    read -r -p "您是否理解以上警告并希望继续? (yes/no): " confirmation
    if [[ "$confirmation" != "yes" ]]; then
        log_message "用户取消了扫描操作。"
        echo "扫描已取消。"
        exit 0
    fi

    log_message "开始 masscan 扫描..."
    local interface_opts=""

    if $SUDO_CMD masscan 0.0.0.0/0 -p"$TARGET_PORT" --excludefile "$EXCLUDE_FILE" --rate "$SCAN_RATE" --wait "$WAIT_DURATION" -oJ "$OUTPUT_FILE" $interface_opts; then
        log_message "masscan 扫描完成。结果已保存到 $OUTPUT_FILE。"
        echo "扫描完成。结果已保存到 $OUTPUT_FILE。"
        echo "发现的开放端口数量: $(wc -l < "$OUTPUT_FILE" | tr -d ' ')"
    else
        log_message "错误: masscan 扫描失败。请检查日志和 masscan 的输出。"
        echo "错误: masscan 扫描失败。请检查日志和 masscan 的输出。"
        exit 1
    fi
}

# --- 主程序 ---
main() {
    > "$LOG_FILE"
    log_message "脚本开始执行。"

    install_masscan_and_deps
    generate_exclude_list

    echo ""
    echo "文件 '$EXCLUDE_FILE' 已生成/更新。"
    echo "强烈建议您现在打开并检查此文件，特别是添加您自己的公网 IP 地址以避免扫描自己。"
    echo "按 Enter键 继续，或按 Ctrl+C 中止并编辑文件..."
    read -r

    run_masscan

    log_message "脚本执行完毕。"
}

# 执行主程序
main