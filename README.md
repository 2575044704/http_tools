# 扫描某个IP所有端口
## 扫描tcp半握手（极快，但只能识别开放的端口，不能识别网页内容）
```bash scan.sh```
## 扫描tcp+http (中等，可以识别网页内容)
```python ./webscan_plus.py "112.219.144.187" -p 1-12000```
## 仅扫描http （极慢，）
```python ./webscan.py "34.88.205.138" -p 1-65535```
# 扫描文件里的IP的8188端口是否为comfyui
```./batch_webscan.sh /home/cn42083120024/test/web_ip_4.txt```
