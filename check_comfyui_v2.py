import json
import requests
from requests.exceptions import RequestException
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re
import gc  # 垃圾回收

# --- 配置 ---
JSON_FILE_PATH = "/home/cn42083120024/masscan/tool/results_8188-2.json"
TARGET_PORT = 8188
COMFYUI_KEYWORDS = [
    "comfyui",
]
REQUEST_TIMEOUT = 6
LOG_FILE = "comfyui_scan.log"
RESULTS_FILE = "comfyui_found_hosts.json"
MAX_WORKERS = 100  # 恢复到100个并发线程（但保持其他内存优化）
MAX_CONTENT_SIZE = 1024 * 1024 # 限制读取内容大小为1MB
CHUNK_SIZE = 1024 * 8  # 8KB chunks for streaming
# --- 配置结束 ---

# --- 日志配置 ---
logger = logging.getLogger("ComfyUIScanner")
logger.setLevel(logging.DEBUG)  # 保持DEBUG级别以便调试

if not logger.handlers:
    try:
        # 添加日志轮转，防止单个日志文件过大
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(LOG_FILE, mode='a', maxBytes=10*1024*1024, 
                                backupCount=3, encoding='utf-8')
        fh.setLevel(logging.INFO)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')
        fh.setFormatter(file_formatter)
        logger.addHandler(fh)
    except ImportError:
        # 如果没有RotatingFileHandler，使用普通FileHandler
        fh = logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8')
        fh.setLevel(logging.INFO)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')
        fh.setFormatter(file_formatter)
        logger.addHandler(fh)
    except Exception as e:
        print(f"CRITICAL: Failed to configure file logger for {LOG_FILE}: {e}")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    ch.setFormatter(console_formatter)
    logger.addHandler(ch)
# --- 日志配置结束 ---


def extract_title_from_stream(content):
    """从流式内容中提取title"""
    try:
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            title = ' '.join(title.split())
            return title
    except Exception:
        pass
    return None


def check_if_comfyui(ip, port):
    """
    通过HTTP请求检查指定IP和端口是否托管ComfyUI。
    使用流式读取来限制内存使用。
    """
    url = f"http://{ip}:{port}/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    logger.debug(f"正在检查: {url}")
    start_time = datetime.now()
    response = None
    
    try:
        # 使用stream=True进行流式读取
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, stream=True)
        response.raise_for_status()
        
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # 限制读取的内容大小
        content_chunks = []
        total_size = 0
        
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                # 确保chunk是字符串类型
                if isinstance(chunk, bytes):
                    try:
                        chunk = chunk.decode('utf-8', errors='ignore')
                    except Exception:
                        chunk = chunk.decode('latin-1', errors='ignore')
                
                content_chunks.append(chunk)
                total_size += len(chunk)
                
                # 如果已经读取了足够的内容来检查关键词和标题，就停止
                if total_size >= MAX_CONTENT_SIZE:
                    logger.debug(f"内容大小超过限制 ({MAX_CONTENT_SIZE} bytes)，停止读取: {url}")
                    break
        
        # 合并内容
        content = ''.join(content_chunks)
        content_lower = content.lower()
        
        # 清理内存
        del content_chunks
        
        # 提取页面标题
        page_title = extract_title_from_stream(content)
        
        # 检查关键词
        for keyword in COMFYUI_KEYWORDS:
            if keyword.lower() in content_lower:
                msg = f"✓ 发现ComfyUI: {url} (关键词: '{keyword}', 响应时间: {response_time:.2f}ms)"
                logger.info(msg)
                return True, msg, keyword, ip, response_time, page_title
        
        # 未找到关键词
        if page_title:
            msg = f"访问成功但非ComfyUI: {url} (标题: '{page_title}')"
            logger.debug(msg)
        else:
            msg = f"访问成功但非ComfyUI: {url}"
            logger.debug(msg)
        return False, msg, None, ip, response_time, page_title
        
    except requests.exceptions.Timeout:
        msg = f"超时: {url}"
        logger.warning(msg)
        return False, msg, None, ip, None, None
    except requests.exceptions.ConnectionError:
        msg = f"连接失败: {url}"
        logger.debug(msg)  # 连接失败很常见，用debug级别
        return False, msg, None, ip, None, None
    except requests.exceptions.HTTPError as e:
        msg = f"HTTP错误: {url} - {e.response.status_code}"
        logger.warning(msg)
        return False, msg, None, ip, None, None
    except Exception as e:
        msg = f"未知错误: {url} - {str(e)}"
        logger.error(msg)
        return False, msg, None, ip, None, None
    finally:
        # 确保关闭响应对象，释放连接
        if response is not None:
            response.close()


def process_batch(ip_batch, batch_num, total_batches):
    """处理一批IP地址"""
    results = []
    accessible = []
    
    logger.info(f"处理批次 {batch_num}/{total_batches} ({len(ip_batch)} IPs)")
    
    # 添加进度计数器
    processed_in_batch = 0
    found_in_batch = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(check_if_comfyui, ip, TARGET_PORT): ip for ip in ip_batch}
        
        for future in as_completed(future_to_ip):
            try:
                is_comfy, log_msg, keyword, ip, resp_time, title = future.result()
                
                if is_comfy:
                    host_info = {
                        "url": f"http://{ip}:{TARGET_PORT}/",
                        "ip": ip,
                        "port": TARGET_PORT,
                        "keyword_found": keyword,
                        "response_time_ms": resp_time,
                        "page_title": title,
                        "discovered_at": datetime.now().isoformat()
                    }
                    results.append(host_info)
                    found_in_batch += 1
                    
                    # 实时写入发现的ComfyUI URL
                    try:
                        with open("comfyui_urls_realtime.txt", 'a', encoding='utf-8') as f:
                            f.write(f"{host_info['url']}\n")
                            f.flush()  # 立即刷新到磁盘
                    except Exception as e:
                        logger.error(f"写入实时结果文件失败: {e}")
                elif resp_time is not None:
                    accessible_info = {
                        "url": f"http://{ip}:{TARGET_PORT}/",
                        "ip": ip,
                        "port": TARGET_PORT,
                        "page_title": title,
                        "response_time_ms": resp_time,
                        "discovered_at": datetime.now().isoformat()
                    }
                    accessible.append(accessible_info)
                    
                    # 对于有标题的非ComfyUI服务，也记录一下
                    if title:
                        logger.info(f"  → 可访问服务: {ip} - {title[:50]}...")
                
                processed_in_batch += 1
                
                # 每处理50个IP输出一次进度
                if processed_in_batch % 50 == 0:
                    logger.info(f"  批次进度: {processed_in_batch}/{len(ip_batch)} " 
                               f"(本批发现 {found_in_batch} 个ComfyUI)")
                    
            except Exception as e:
                logger.error(f"处理IP {future_to_ip[future]} 时出错: {e}")
    
    logger.info(f"批次 {batch_num} 完成: 发现 {found_in_batch} 个ComfyUI, "
               f"{len(accessible)} 个其他可访问服务")
    
    return results, accessible


def main():
    logger.info(f"开始ComfyUI扫描 (线程数: {MAX_WORKERS})")
    
    # 清空实时结果文件
    try:
        open("comfyui_urls_realtime.txt", 'w').close()
    except Exception:
        pass
    
    scan_start_time = datetime.now()
    
    # 读取JSON文件
    try:
        with open(JSON_FILE_PATH, 'r', encoding='utf-8') as f:
            results_from_json = json.load(f)
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        return
    
    # 筛选需要检查的IP
    ips_to_check = []
    for item in results_from_json:
        ip = item.get("ip")
        if not ip:
            continue
            
        ports_info = item.get("ports", [])
        for port_detail in ports_info:
            if port_detail.get("port") == TARGET_PORT and port_detail.get("status") == "open":
                ips_to_check.append(ip)
                break
    
    total_to_scan = len(ips_to_check)
    if total_to_scan == 0:
        logger.info("没有找到需要扫描的IP")
        return
    
    logger.info(f"准备扫描 {total_to_scan} 个IP地址...")
    
    # 分批处理，避免一次性加载过多结果到内存
    BATCH_SIZE = 500
    all_comfyui_hosts = []
    all_accessible_hosts = []
    
    # 添加统计信息
    total_processed = 0
    total_timeouts = 0
    total_connection_errors = 0
    
    logger.info(f"配置: 线程数={MAX_WORKERS}, 超时={REQUEST_TIMEOUT}秒, 批次大小={BATCH_SIZE}")
    
    for i in range(0, total_to_scan, BATCH_SIZE):
        batch = ips_to_check[i:i+BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        total_batches = (total_to_scan + BATCH_SIZE - 1) // BATCH_SIZE
        
        comfyui_batch, accessible_batch = process_batch(batch, batch_num, total_batches)
        
        all_comfyui_hosts.extend(comfyui_batch)
        all_accessible_hosts.extend(accessible_batch)
        
        # 定期保存结果，避免丢失
        if batch_num % 5 == 0:
            temp_results = {
                "scan_time": scan_start_time.isoformat(),
                "status": "in_progress",
                "progress": f"{min(i+BATCH_SIZE, total_to_scan)}/{total_to_scan}",
                "comfyui_hosts_found": len(all_comfyui_hosts),
                "hosts": all_comfyui_hosts
            }
            with open(f"{RESULTS_FILE}.tmp", 'w', encoding='utf-8') as f:
                json.dump(temp_results, f, ensure_ascii=False, indent=2)
        
        # 强制垃圾回收
        gc.collect()
        
        logger.info(f"已处理 {min(i+BATCH_SIZE, total_to_scan)}/{total_to_scan} IPs "
                   f"({(min(i+BATCH_SIZE, total_to_scan)/total_to_scan*100):.1f}%), "
                   f"发现 {len(all_comfyui_hosts)} 个ComfyUI实例, "
                   f"{len(all_accessible_hosts)} 个其他可访问服务")
    
    # 保存最终结果
    scan_end_time = datetime.now()
    results_data = {
        "scan_time": scan_start_time.isoformat(),
        "scan_end_time": scan_end_time.isoformat(),
        "scan_duration_seconds": (scan_end_time - scan_start_time).total_seconds(),
        "total_ips_scanned": total_to_scan,
        "comfyui_hosts_found": len(all_comfyui_hosts),
        "accessible_hosts_found": len(all_accessible_hosts),
        "hosts": sorted(all_comfyui_hosts, key=lambda x: x['ip']),
        "accessible_non_comfyui_hosts": sorted(all_accessible_hosts, key=lambda x: x['ip'])[:100]  # 只保存前100个
    }
    
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(results_data, f, ensure_ascii=False, indent=2)
    
    # 保存URL列表
    with open("comfyui_urls.txt", 'w', encoding='utf-8') as f:
        unique_urls = sorted(set(host['url'] for host in all_comfyui_hosts))
        for url in unique_urls:
            f.write(f"{url}\n")
    
    # 保存URL列表
    with open("comfyui_urls.txt", 'w', encoding='utf-8') as f:
        unique_urls = sorted(set(host['url'] for host in all_comfyui_hosts))
        for url in unique_urls:
            f.write(f"{url}\n")
    
    # 保存简单的文本报告
    with open("scan_summary.txt", 'w', encoding='utf-8') as f:
        f.write(f"ComfyUI扫描报告\n")
        f.write(f"="*50 + "\n")
        f.write(f"扫描时间: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"扫描耗时: {(scan_end_time - scan_start_time).total_seconds():.2f} 秒\n")
        f.write(f"扫描IP总数: {total_to_scan}\n")
        f.write(f"发现ComfyUI实例: {len(all_comfyui_hosts)}\n")
        f.write(f"其他可访问服务: {len(all_accessible_hosts)}\n")
        f.write(f"\n发现的ComfyUI实例:\n")
        f.write(f"-"*50 + "\n")
        for host in sorted(all_comfyui_hosts, key=lambda x: x['ip']):
            f.write(f"{host['url']} - {host['keyword_found']} - {host['response_time_ms']:.2f}ms\n")
    
    logger.info(f"\n扫描完成！")
    logger.info(f"="*60)
    logger.info(f"扫描耗时: {(scan_end_time - scan_start_time).total_seconds():.2f} 秒")
    logger.info(f"发现 {len(all_comfyui_hosts)} 个ComfyUI实例")
    logger.info(f"发现 {len(all_accessible_hosts)} 个其他可访问服务")
    logger.info(f"="*60)
    logger.info(f"结果文件:")
    logger.info(f"  - JSON详细结果: {RESULTS_FILE}")
    logger.info(f"  - ComfyUI URL列表: comfyui_urls.txt")
    logger.info(f"  - 扫描摘要: scan_summary.txt")
    logger.info(f"  - 详细日志: {LOG_FILE}")


if __name__ == "__main__":
    main()