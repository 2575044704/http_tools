#!/bin/sh

# 检查是否提供了输入文件名作为参数
if [ "$#" -ne 1 ]; then
    echo "用法: $0 <ip_list_file>"
    exit 1
fi

INPUT_FILE="$1"

# 检查输入文件是否存在且可读
if [ ! -f "$INPUT_FILE" ]; then
    echo "错误: 文件 '$INPUT_FILE' 未找到！"
    exit 1
fi

if [ ! -r "$INPUT_FILE" ]; then
    echo "错误: 文件 '$INPUT_FILE' 不可读！"
    exit 1
fi

# 检查 webscan.py 脚本是否存在且可执行
WEBSCAN_SCRIPT="webscan.py" # 假设 webscan.py 在当前目录或 PATH 中
                           # 如果不在，请提供完整路径，例如: WEBSCAN_SCRIPT="/path/to/your/webscan.py"

if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1 ; then
    echo "错误: 未找到 Python解释器 (python 或 python3)。请确保已安装 Python。"
    exit 1
fi

# 优先使用 python3 如果存在
PYTHON_CMD="python"
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
fi


if [ ! -f "$WEBSCAN_SCRIPT" ]; then
    # 尝试在PATH中查找，如果 WEBSCAN_SCRIPT 只是文件名
    if ! command -v "$WEBSCAN_SCRIPT" >/dev/null 2>&1 && [ "$(dirname "$WEBSCAN_SCRIPT")" = "." ]; then
        echo "错误: 脚本 '$WEBSCAN_SCRIPT' 在当前目录或PATH中未找到！"
        exit 1
    elif [ ! -f "$WEBSCAN_SCRIPT" ]; then # 如果是路径但文件不存在
         echo "错误: 脚本 '$WEBSCAN_SCRIPT' 未找到！"
         exit 1
    fi
fi


# 逐行读取输入文件
while IFS= read -r target_ip || [ -n "$target_ip" ]; do
    # 忽略空行或只包含空格的行
    if [ -z "$(echo "$target_ip" | tr -d '[:space:]')" ]; then
        continue
    fi

    echo "----------------------------------------------------"
    echo "正在扫描: $target_ip (端口: 8188)"
    echo "----------------------------------------------------"

    # 执行 python 脚本
    # $PYTHON_CMD "$WEBSCAN_SCRIPT" "$target_ip" -p 8188
    # 或者，如果 webscan.py 有执行权限并且 shebang 正确:
    "$PYTHON_CMD" "$WEBSCAN_SCRIPT" "$target_ip" -p 8188 -j -o output.json

    # 如果想将每个IP的输出保存到单独的文件，可以这样做：
    # OUTPUT_LOG_FILE="scan_result_${target_ip}_8188.txt"
    # echo "将结果保存到: $OUTPUT_LOG_FILE"
    # $PYTHON_CMD "$WEBSCAN_SCRIPT" "$target_ip" -p 8188 > "$OUTPUT_LOG_FILE" 2>&1

    echo "" # 在每次扫描后添加一个空行以便分隔
done < "$INPUT_FILE"

echo "所有目标扫描完成。"