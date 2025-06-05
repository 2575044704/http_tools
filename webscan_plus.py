import socket
import concurrent.futures
import requests
import argparse
import sys
import time
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
DEFAULT_PORTS_TO_SCAN = "80,443,8000-8010,8080-8090,8888,3000,5000" # Common web and dev ports
CONNECT_TIMEOUT = 1  # Timeout for initial port connection (seconds)
HTTP_TIMEOUT = 0.5       # Timeout for HTTP/S requests (seconds)
MAX_WORKERS_PORT_SCAN = 100 # Threads for port scanning
MAX_WORKERS_HTTP_CHECK = 1 # Threads for HTTP checking (lower to avoid overwhelming target)
CONTENT_SNIPPET_LENGTH = 1500 # Max characters of HTTP body to display

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

def scan_port(ip, port, timeout):
    """Scans a single port on the IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port, True
            else:
                return port, False
    except (socket.timeout, socket.error, OSError): # Added OSError for wider coverage
        return port, False

def check_http_on_port(ip, port, http_timeout):
    """Attempts HTTP and HTTPS GET requests on an open port."""
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
        try:
            response_obj = requests.get(url, timeout=http_timeout, verify=False, allow_redirects=True, stream=True)
            
            content_type_header = response_obj.headers.get('Content-Type', '')
            status_text_parts = [f"Status: {response_obj.status_code}"]
            if content_type_header:
                status_text_parts.append(f"Content-Type: {content_type_header.strip()}") # .strip() added
            status_text = f" ({', '.join(status_text_parts)})"

            body_display = ""
            try:
                # Make sure encoding is set if possible before decode_unicode=True is used by iter_content
                # If Content-Type header doesn't specify charset, response_obj.encoding is None.
                # Accessing apparent_encoding will try to guess from content, and set response_obj.encoding.
                # This might read from the stream.
                if response_obj.encoding is None:
                    response_obj.encoding = response_obj.apparent_encoding # Try to guess if not set by headers

                # Now iter_content(decode_unicode=True) will use response_obj.encoding
                first_chunk_str = next(response_obj.iter_content(chunk_size=CONTENT_SNIPPET_LENGTH * 2, decode_unicode=True), "")

                if not first_chunk_str:
                    body_display = "\n      Body: [Empty response body]"
                else:
                    processed_snippet = first_chunk_str.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
                    display_snippet_text = processed_snippet[:CONTENT_SNIPPET_LENGTH]
                    ellipsis = ""
                    if len(first_chunk_str) > CONTENT_SNIPPET_LENGTH or len(processed_snippet) > CONTENT_SNIPPET_LENGTH:
                        ellipsis = "..."
                    
                    final_display_text = display_snippet_text.strip()
                    if not final_display_text:
                        body_display = "\n      Body: [Preview is whitespace or empty after cleaning]"
                    else:
                        body_display = f"\n      Body: {final_display_text}{ellipsis}"
            
            except requests.exceptions.ChunkedEncodingError as e_chunk:
                 body_display = f"\n      Body: [ChunkedEncodingError: {str(e_chunk)[:150]}]"
            except UnicodeError as e_unicode:
                 body_display = f"\n      Body: [UnicodeError: {str(e_unicode)[:150]} (likely binary or wrong encoding)]"
            # Catch more specific requests exceptions before the generic one
            except requests.exceptions.RequestException as e_req:
                 body_display = f"\n      Body: [{type(e_req).__name__}: {str(e_req)[:150]}]"
            except Exception as e_generic: # Catch-all for other issues
                 body_display = f"\n      Body: [Unexpected Error: {type(e_generic).__name__} - {str(e_generic)[:150]}]"
            
            results.append(f"  [{protocol}] {url} - Success{status_text}{body_display}")
            break 

        except requests.exceptions.SSLError:
            results.append(f"  [{protocol}] {url} - SSL Error (try http:// or check cert)")
        except requests.exceptions.ConnectionError: # This could be hit if server refuses connection for HTTP after HTTPS try or vice-versa
            results.append(f"  [{protocol}] {url} - Connection Error (No server or wrong protocol?)")
        except requests.exceptions.Timeout:
            results.append(f"  [{protocol}] {url} - Request Timeout")
        except requests.exceptions.RequestException as e: # General requests error for the main GET
            results.append(f"  [{protocol}] {url} - Error: {type(e).__name__} ({str(e)[:100]})")
        finally:
            if response_obj:
                response_obj.close()
    return port, results
# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="Scan an IP for open ports and attempt HTTP/S requests.")
    parser.add_argument("target_ip", help="The IP address to scan.")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS_TO_SCAN,
                        help=f"Comma-separated list of ports/port-ranges (e.g., 80,443,8000-8010). Default: '{DEFAULT_PORTS_TO_SCAN}'. Use '1-65535' for all.")
    parser.add_argument("-ct", "--connect-timeout", type=float, default=CONNECT_TIMEOUT,
                        help=f"Timeout for port connection in seconds. Default: {CONNECT_TIMEOUT}")
    parser.add_argument("-ht", "--http-timeout", type=float, default=HTTP_TIMEOUT,
                        help=f"Timeout for HTTP/S requests in seconds. Default: {HTTP_TIMEOUT}")
    parser.add_argument("-wps", "--workers-port-scan", type=int, default=MAX_WORKERS_PORT_SCAN,
                        help=f"Number of concurrent threads for port scanning. Default: {MAX_WORKERS_PORT_SCAN}")
    parser.add_argument("-whttp", "--workers-http-check", type=int, default=MAX_WORKERS_HTTP_CHECK,
                        help=f"Number of concurrent threads for HTTP checking. Default: {MAX_WORKERS_HTTP_CHECK}")

    args = parser.parse_args()

    try:
        socket.inet_aton(args.target_ip)
    except socket.error:
        print(f"Error: Invalid IP address '{args.target_ip}'", file=sys.stderr)
        sys.exit(1)

    ports_to_scan = parse_port_range(args.ports)
    if not ports_to_scan:
        print("No ports specified or parsed correctly.")
        sys.exit(1)

    print(f"Scanning {args.target_ip} for {len(ports_to_scan)} ports (Timeout: {args.connect_timeout}s for connect, {args.http_timeout}s for HTTP)...")
    print(f"Ports to scan: {', '.join(map(str, ports_to_scan[:10]))}{'...' if len(ports_to_scan) > 10 else ''}")

    open_ports = []
    start_time_script = time.time() # Overall script start time

    start_time_scan = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers_port_scan) as executor:
        future_to_port_scan = {executor.submit(scan_port, args.target_ip, port, args.connect_timeout): port for port in ports_to_scan}
        
        scanned_count = 0
        total_ports_to_scan = len(ports_to_scan)
        for future in concurrent.futures.as_completed(future_to_port_scan):
            port, is_open = future.result()
            scanned_count += 1
            progress = (scanned_count / total_ports_to_scan) * 100
            sys.stdout.write(f"\rPort Scanning Progress: {scanned_count}/{total_ports_to_scan} ({progress:.2f}%)")
            sys.stdout.flush()
            if is_open:
                open_ports.append(port)
    
    sys.stdout.write("\r" + " " * 80 + "\r") 
    sys.stdout.flush()
    scan_duration = time.time() - start_time_scan
    print(f"Port scanning complete in {scan_duration:.2f} seconds.")

    if not open_ports:
        print("No open ports found in the specified range.")
        total_duration = time.time() - start_time_script
        print(f"\nTotal script execution time: {total_duration:.2f} seconds.")
        return

    open_ports.sort()
    print(f"\nFound {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}")
    print("\nAttempting HTTP/S requests on open ports...")

    start_time_http = time.time()
    http_checked_count = 0
    total_open_ports = len(open_ports)
    results_map = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers_http_check) as executor:
        future_to_http_check = {executor.submit(check_http_on_port, args.target_ip, port, args.http_timeout): port for port in open_ports}
        
        for future in concurrent.futures.as_completed(future_to_http_check):
            port, http_results = future.result()
            results_map[port] = http_results
            http_checked_count +=1
            progress_http = (http_checked_count / total_open_ports) * 100
            sys.stdout.write(f"\rHTTP Check Progress: {http_checked_count}/{total_open_ports} ({progress_http:.2f}%)")
            sys.stdout.flush()

    sys.stdout.write("\r" + " " * 80 + "\r") 
    sys.stdout.flush()
    http_duration = time.time() - start_time_http
    print(f"HTTP checking complete in {http_duration:.2f} seconds.")

    print("\n--- HTTP/S Check Results ---")
    if results_map:
        for port in open_ports: 
            if port in results_map:
                print(f"Port {port}:")
                for res_line in results_map[port]:
                    print(res_line)
            # else: # This case should ideally not happen if all open ports are processed
            #    print(f"Port {port}: [No HTTP/S results gathered]") 
    else:
        print("No HTTP/S responses received from open ports (or no open ports were suitable for HTTP check).")
        
    total_duration = time.time() - start_time_script
    print(f"\nTotal script execution time: {total_duration:.2f} seconds.")

if __name__ == "__main__":
    main()