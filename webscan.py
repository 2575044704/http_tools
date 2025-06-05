import socket
import concurrent.futures
import requests
import argparse
import sys
import time
import json
import os
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
DEFAULT_PORTS_TO_SCAN = "80,443,8000-8010,8080-8090,8888,3000,5000" # Common web and dev ports
HTTP_TIMEOUT = 2       # Timeout for HTTP/S requests (seconds)
MAX_WORKERS_HTTP_CHECK = 1 # Threads for HTTP checking (user can override with -whttp)
CONTENT_SNIPPET_LENGTH = 300 # Max characters of HTTP body to display

# --- Helper Functions ---
def parse_port_range(port_str):
    """Parses a port string like "80,443,8000-8010" into a list of ports."""
    ports = set()
    if not port_str:
        return sorted(list(ports))
    try:
        for part in port_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (0 < start <= 65535 and 0 < end <= 65535 and start <= end):
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            else:
                port_num = int(part)
                if not (0 < port_num <= 65535):
                    raise ValueError(f"Invalid port number: {port_num}")
                ports.add(port_num)
    except ValueError as e:
        print(f"Error parsing port string '{port_str}': {e}", file=sys.stderr)
        sys.exit(1)
    return sorted(list(ports))

def check_http_on_port(ip, port, http_timeout, port_index):
    """Attempts HTTP and HTTPS GET requests on a given port."""
    results = []
    urls_to_try = []

    if port in [443, 8443]: # Prioritize HTTPS for common HTTPS ports
        urls_to_try.append(f"https://{ip}:{port}")
        urls_to_try.append(f"http://{ip}:{port}")
    else:
        urls_to_try.append(f"http://{ip}:{port}")
        urls_to_try.append(f"https://{ip}:{port}")

    response_obj = None

    for url in urls_to_try:
        protocol = "HTTPS" if url.startswith("https") else "HTTP"
        result = {
            "id": port_index,
            "url": url,
            "status": None,
            "content": None,
            "ip": ip,
            "port": port,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        
        try:
            response_obj = requests.get(url, timeout=http_timeout, verify=False, allow_redirects=True, stream=True)
            result["status"] = response_obj.status_code
            
            try:
                if response_obj.encoding is None:
                    response_obj.encoding = response_obj.apparent_encoding

                first_chunk = next(response_obj.iter_content(chunk_size=CONTENT_SNIPPET_LENGTH * 2, decode_unicode=True), "")

                if not first_chunk:
                    result["content"] = ""
                else:
                    processed_snippet = first_chunk.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
                    display_snippet_text = processed_snippet[:CONTENT_SNIPPET_LENGTH]
                    result["content"] = display_snippet_text.strip()
            
            except requests.exceptions.ChunkedEncodingError as e_chunk:
                result["content"] = f"ChunkedEncodingError: {str(e_chunk)[:150]}"
            except UnicodeError as e_unicode:
                result["content"] = f"UnicodeError: {str(e_unicode)[:150]} (likely binary or wrong encoding)"
            except requests.exceptions.RequestException as e_req:
                result["content"] = f"{type(e_req).__name__}: {str(e_req)[:150]}"
            except Exception as e_generic: 
                result["content"] = f"Unexpected Error: {type(e_generic).__name__} - {str(e_generic)[:150]}"
            
            results.append(result)
            break # Found a working protocol for this port, stop trying others

        except requests.exceptions.SSLError:
            result["status"] = "SSL Error"
            result["content"] = "SSL Error (try http:// or check cert)"
            results.append(result)
        except requests.exceptions.ConnectionError:
            result["status"] = "Connection Error"
            result["content"] = "Connection Error (No server or wrong protocol?)"
            results.append(result)
        except requests.exceptions.Timeout:
            result["status"] = "Timeout"
            result["content"] = "Request Timeout"
            results.append(result)
        except requests.exceptions.RequestException as e:
            result["status"] = type(e).__name__
            result["content"] = f"Error: {str(e)[:150]}"
            results.append(result)
        finally:
            if response_obj:
                response_obj.close() # Ensure connection is closed, especially with stream=True
    
    return port, results

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="Directly attempts HTTP/S requests on specified ports for a target IP.")
    parser.add_argument("target_ip", help="The IP address to target.")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS_TO_SCAN,
                        help=f"Comma-separated list of ports/port-ranges to attempt HTTP/S on (e.g., 80,443,8000-8010). Default: '{DEFAULT_PORTS_TO_SCAN}'. Use '1-65535' for all.")
    parser.add_argument("-ht", "--http-timeout", type=float, default=HTTP_TIMEOUT,
                        help=f"Timeout for HTTP/S requests in seconds. Default: {HTTP_TIMEOUT}")
    parser.add_argument("-whttp", "--workers-http-check", type=int, default=MAX_WORKERS_HTTP_CHECK,
                        help=f"Number of concurrent threads for HTTP/S requests. Default: {MAX_WORKERS_HTTP_CHECK}")
    parser.add_argument("-j", "--json-output", action="store_true",
                        help="Output results in JSON format")
    parser.add_argument("-o", "--output-file", 
                        help="Write results to specified file instead of stdout")

    args = parser.parse_args()

    try:
        socket.inet_aton(args.target_ip)
    except socket.error:
        print(f"Error: Invalid IP address '{args.target_ip}'", file=sys.stderr)
        sys.exit(1)

    ports_to_check = parse_port_range(args.ports)
    if not ports_to_check:
        print("No ports specified or parsed correctly.")
        sys.exit(1)

    # Only show verbose progress info if not using JSON output
    if not args.json_output:
        print(f"Attempting HTTP/S on {args.target_ip} for {len(ports_to_check)} port(s) (HTTP Timeout: {args.http_timeout}s)...")
        print(f"Ports to check: {', '.join(map(str, ports_to_check[:10]))}{'...' if len(ports_to_check) > 10 else ''}")

    start_time_script = time.time() # Overall script start time

    if not args.json_output:
        print("\nStarting HTTP/S request attempts on specified ports...")

    start_time_http = time.time()
    http_checked_count = 0
    total_ports_to_check_http = len(ports_to_check)
    results_map = {} # Stores results for each port
    json_results = []

    # Create a list of port indices to track original order
    port_indices = {port: i+1 for i, port in enumerate(ports_to_check)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers_http_check) as executor:
        # Submit tasks to check HTTP/S on all specified ports directly
        future_to_http_check = {executor.submit(check_http_on_port, args.target_ip, port, args.http_timeout, port_indices[port]): port for port in ports_to_check}
        
        for future in concurrent.futures.as_completed(future_to_http_check):
            port, http_results = future.result()
            # http_results will always be a list (possibly of error messages), so store it.
            results_map[port] = http_results
            http_checked_count +=1
            
            # Only show progress if not using JSON output
            if not args.json_output:
                progress_http = (http_checked_count / total_ports_to_check_http) * 100
                sys.stdout.write(f"\rHTTP/S Request Progress: {http_checked_count}/{total_ports_to_check_http} ({progress_http:.2f}%)")
                sys.stdout.flush()

    if not args.json_output:
        sys.stdout.write("\r" + " " * 80 + "\r") # Clear progress line
        sys.stdout.flush()
        http_duration = time.time() - start_time_http
        print(f"HTTP/S request phase complete in {http_duration:.2f} seconds.")

    # Prepare JSON output
    for port_num in ports_to_check: 
        if port_num in results_map:
            for result in results_map[port_num]:
                json_results.append(result)
    
    # Output results
    if args.json_output:
        # 先读取现有的JSON文件（如果存在）
        existing_results = []
        if args.output_file and os.path.exists(args.output_file):
            try:
                with open(args.output_file, 'r', encoding='utf-8') as f:
                    existing_content = f.read().strip()
                    if existing_content:
                        existing_results = json.loads(existing_content)
            except json.JSONDecodeError:
                print(f"Warning: Could not parse existing JSON file {args.output_file}, will create new file", file=sys.stderr)
            except Exception as e:
                print(f"Warning: Error reading existing file {args.output_file}: {str(e)}", file=sys.stderr)
        
        # 合并结果（保留现有结果并添加新结果）
        combined_results = existing_results + json_results
        
        # 按ID排序（可选）
        combined_results.sort(key=lambda x: x.get('id', float('inf')))
        
        json_data = json.dumps(combined_results, indent=2)
        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    f.write(json_data)
                print(f"Results written to {args.output_file}")
            except Exception as e:
                print(f"Error writing to file {args.output_file}: {str(e)}", file=sys.stderr)
                sys.exit(1)
        else:
            print(json_data)
    else:
        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    f.write("--- HTTP/S Check Results ---\n")
                    for port_num in ports_to_check:
                        if port_num in results_map:
                            f.write(f"Port {port_num}:\n")
                            for result in results_map[port_num]:
                                f.write(f"  [ID: {result['id']}] {result['url']} - Status: {result['status']}\n")
                                f.write(f"      Content: {result['content']}\n")
                        else:
                            f.write(f"Port {port_num}: [Warning: No results found for this port.]\n")
                    
                    total_duration = time.time() - start_time_script
                    f.write(f"\nTotal script execution time: {total_duration:.2f} seconds.\n")
                print(f"Results written to {args.output_file}")
            except Exception as e:
                print(f"Error writing to file {args.output_file}: {str(e)}", file=sys.stderr)
                sys.exit(1)
        else:
            print("\n--- HTTP/S Check Results ---")
            # Iterate through the ports in the order they were specified
            for port_num in ports_to_check: 
                if port_num in results_map:
                    print(f"Port {port_num}:")
                    for result in results_map[port_num]:
                        print(f"  [ID: {result['id']}] {result['url']} - Status: {result['status']}")
                        print(f"      Content: {result['content']}")
                else:
                    print(f"Port {port_num}: [Warning: No results found for this port.]")
            
            total_duration = time.time() - start_time_script
            print(f"\nTotal script execution time: {total_duration:.2f} seconds.")

if __name__ == "__main__":
    main()