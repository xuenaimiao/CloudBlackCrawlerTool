import time
import pandas as pd
import os
import logging
import re
import json
import requests
import threading
import socket
import sys
import pickle
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import base64
import random
import ssl
from bs4 import BeautifulSoup
# 导入配置文件
from config import *

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("crawler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局变量，存储当前使用的远程代理
current_remote_proxy = {
    "host": None,
    "port": None,
    "ip_info": None  # 存储当前代理的IP信息
}

# 全局变量，记录上次代理切换时间
last_proxy_change_time = 0

# 结果数据，格式为: [{"qq": "xxx", "result": "xxx", "result_type": "xxx", "ip_used": "xxx", "time": "xxx"}]
query_results = []

# 记录当前查询进度
query_progress = {
    "current_range_index": 0,  # 当前查询的范围索引
    "current_position": 0,  # 当前查询到的QQ号码
    "ranges": QUERY_RANGES.copy()  # 复制查询范围
}

class ProxyRequestHandler(BaseHTTPRequestHandler):
    """本地代理服务器的请求处理器"""
    
    def do_CONNECT(self):
        """处理HTTPS连接请求"""
        try:
            # 解析目标主机和端口
            host, port = self.path.split(':')
            port = int(port)
            
            # 创建到远程代理的连接
            if current_remote_proxy["host"] and current_remote_proxy["port"]:
                # 使用远程代理
                proxy_host = current_remote_proxy["host"]
                proxy_port = int(current_remote_proxy["port"])
                
                # 创建到远程代理的连接
                proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_socket.connect((proxy_host, proxy_port))
                
                # 发送代理认证
                auth = f"{AUTH_KEY}:{PASSWORD}"
                auth_header = f"Proxy-Authorization: Basic {base64.b64encode(auth.encode()).decode()}\r\n"
                auth_header += f"Authorization: Basic {base64.b64encode(auth.encode()).decode()}\r\n"
                
                # 发送CONNECT请求到远程代理
                connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth_header}\r\n"
                proxy_socket.sendall(connect_request.encode())
                
                # 读取代理响应
                response = proxy_socket.recv(4096)
                
                # 发送200连接成功响应给客户端
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                
                # 在客户端和远程代理之间转发数据
                self._forward_data(self.connection, proxy_socket)
            else:
                # 直接连接到目标主机
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.connect((host, port))
                
                # 发送200连接成功响应给客户端
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                
                # 在客户端和目标主机之间转发数据
                self._forward_data(self.connection, remote_socket)
        
        except Exception as e:
            logger.error(f"处理CONNECT请求时出错: {e}")
    
    def do_GET(self):
        """处理HTTP GET请求"""
        try:
            # 解析URL
            url = self.path
            parsed_url = urlparse(url)
            
            # 构建请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # 从请求中获取头部
            for header in self.headers:
                if header.lower() not in ['host', 'connection', 'proxy-connection', 'proxy-authorization']:
                    headers[header] = self.headers[header]
            
            # 添加代理认证头部
            auth = f"{AUTH_KEY}:{PASSWORD}"
            headers['Proxy-Authorization'] = f"Basic {base64.b64encode(auth.encode()).decode()}"
            headers['Authorization'] = f"Basic {base64.b64encode(auth.encode()).decode()}"
            
            # 使用远程代理
            if current_remote_proxy["host"] and current_remote_proxy["port"]:
                proxies = {
                    'http': f'http://{AUTH_KEY}:{PASSWORD}@{current_remote_proxy["host"]}:{current_remote_proxy["port"]}',
                    'https': f'http://{AUTH_KEY}:{PASSWORD}@{current_remote_proxy["host"]}:{current_remote_proxy["port"]}'
                }
                
                # 发送请求
                response = requests.get(url, headers=headers, proxies=proxies, verify=False)
            else:
                # 直接发送请求
                response = requests.get(url, headers=headers, verify=False)
            
            # 返回响应
            self.send_response(response.status_code)
            
            # 设置响应头
            for key, value in response.headers.items():
                if key.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(key, value)
            
            self.end_headers()
            
            # 发送响应内容
            self.wfile.write(response.content)
        
        except Exception as e:
            logger.error(f"处理GET请求时出错: {e}")
            self.send_error(500, str(e))
    
    def _forward_data(self, client_socket, remote_socket):
        """在两个套接字之间转发数据"""
        client_to_remote = threading.Thread(target=self._forward, args=(client_socket, remote_socket))
        remote_to_client = threading.Thread(target=self._forward, args=(remote_socket, client_socket))
        
        client_to_remote.daemon = True
        remote_to_client.daemon = True
        
        client_to_remote.start()
        remote_to_client.start()
        
        # 等待线程结束
        client_to_remote.join()
        remote_to_client.join()
    
    def _forward(self, source, destination):
        """从源套接字读取数据并发送到目标套接字"""
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)
        except:
            pass
        finally:
            try:
                source.close()
            except:
                pass

def start_local_proxy_server():
    """启动本地代理服务器"""
    try:
        server = ThreadingHTTPServer(('127.0.0.1', LOCAL_PROXY_PORT), ProxyRequestHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        logger.info(f"本地代理服务器已启动在 127.0.0.1:{LOCAL_PROXY_PORT}")
        return server
    except Exception as e:
        logger.error(f"启动本地代理服务器失败: {e}")
        return None

def get_proxy():
    """获取代理IP"""
    try:
        response = requests.get(PROXY_API_URL)
        data = response.json()
        
        if data.get("code") == 'SUCCESS' and data.get("data"):
            proxy_data = data["data"][0]
            server = proxy_data.get("server")
            
            if server and ":" in server:
                proxy_host, proxy_port = server.split(":")
                logger.info(f"成功获取代理IP: {proxy_host}:{proxy_port}")
                return proxy_host, proxy_port
        
        logger.error(f"获取代理IP失败: {data}")
        return None, None
    
    except Exception as e:
        logger.error(f"获取代理IP时出错: {e}")
        return None, None

def verify_proxy(proxy_host, proxy_port):
    """验证代理是否可用"""
    try:
        if not proxy_host or not proxy_port:
            return False
            
        proxies = {
            'http': f'http://{AUTH_KEY}:{PASSWORD}@{proxy_host}:{proxy_port}',
            'https': f'http://{AUTH_KEY}:{PASSWORD}@{proxy_host}:{proxy_port}'
        }
        response = requests.get(IP_CHECK_URL, proxies=proxies, timeout=10, verify=False)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"验证代理时出错: {proxy_host}:{proxy_port}, {str(e)}")
        return False

def get_working_proxy():
    """获取可用的代理，如果多次尝试失败则退出程序"""
    for retry in range(MAX_PROXY_RETRIES):
        logger.info(f"尝试获取代理 (尝试 {retry+1}/{MAX_PROXY_RETRIES})...")
        proxy_host, proxy_port = get_proxy()

        if proxy_host and proxy_port and verify_proxy(proxy_host, proxy_port):
            return proxy_host, proxy_port

        time.sleep(2)  # 增加重试间隔

    logger.error(f"连续 {MAX_PROXY_RETRIES} 次无法获取可用代理，程序将终止")
    sys.exit(1)  # 终止程序

def get_current_ip_info(proxy_host=None, proxy_port=None):
    """获取当前IP信息"""
    try:
        # 如果没有提供代理，则返回None，不使用本地IP
        if not proxy_host or not proxy_port:
            logger.warning("没有可用的代理，无法获取IP信息")
            return "未知IP"

        headers = {
            'User-Agent': get_random_user_agent()
        }

        proxies = {
            'http': f'http://{AUTH_KEY}:{PASSWORD}@{proxy_host}:{proxy_port}',
            'https': f'http://{AUTH_KEY}:{PASSWORD}@{proxy_host}:{proxy_port}'
        }

        response = requests.get(IP_CHECK_URL, headers=headers, proxies=proxies, timeout=10, verify=False)

        if response.status_code == 200:
            ip_info = response.text.strip()
            logger.info(f"当前IP信息: {ip_info}")
            return ip_info
        else:
            logger.error(f"获取IP信息失败，状态码: {response.status_code}")
            return "获取IP失败"
    except Exception as e:
        logger.error(f"获取IP信息时出错: {e}")
        return "获取IP出错"

def change_proxy():
    """切换代理IP，如果失败则终止程序"""
    global last_proxy_change_time
    logger.info("正在切换代理IP...")

    try:
        # 获取新代理 - 如果无法获取，get_working_proxy 会自动终止程序
        proxy_host, proxy_port = get_working_proxy()

        # 更新全局代理设置
        current_remote_proxy["host"] = proxy_host
        current_remote_proxy["port"] = proxy_port

        # 获取当前IP信息
        ip_info = get_current_ip_info(proxy_host, proxy_port)
        current_remote_proxy["ip_info"] = ip_info

        # 更新上次代理切换时间
        last_proxy_change_time = time.time()

        logger.info(f"成功切换到新代理: {proxy_host}:{proxy_port}")
        logger.info(f"当前IP信息: {ip_info}")
        return True
    except Exception as e:
        logger.error(f"切换代理时出错: {e}")
        return False

def get_random_user_agent():
    """生成随机的用户代理，增强随机性避免被识别"""
    # 常见操作系统
    os_list = [
        'Windows NT 10.0; Win64; x64',
        'Windows NT 6.1; Win64; x64',
        'Macintosh; Intel Mac OS X 10_15_7',
        'Macintosh; Intel Mac OS X 10_14_6',
        'X11; Linux x86_64',
        'X11; Ubuntu; Linux x86_64',
        'Windows NT 11.0; Win64; x64',
    ]
    
    # 常见浏览器及其版本
    browsers = [
        f'Chrome/{random.randint(90, 134)}.0.{random.randint(1000, 9999)}.{random.randint(10, 999)}',
        f'Firefox/{random.randint(80, 120)}.0',
        f'Safari/{random.randint(600, 615)}.{random.randint(1, 36)}',
        f'Edge/{random.randint(90, 120)}.0.{random.randint(100, 999)}.{random.randint(10, 99)}',
        f'OPR/{random.randint(70, 95)}.0.{random.randint(1000, 9999)}.{random.randint(10, 999)}',
    ]
    
    # 选择随机的操作系统和浏览器
    selected_os = random.choice(os_list)
    selected_browser = random.choice(browsers)
    
    # 构建随机的用户代理字符串
    if 'Chrome' in selected_browser or 'Edge' in selected_browser or 'OPR' in selected_browser:
        webkit_version = f'{random.randint(500, 537)}.{random.randint(30, 36)}'
        user_agent = f'Mozilla/5.0 ({selected_os}) AppleWebKit/{webkit_version} (KHTML, like Gecko) {selected_browser}'
    elif 'Firefox' in selected_browser:
        gecko_version = f'{random.randint(20200101, 20231231)}'
        user_agent = f'Mozilla/5.0 ({selected_os}; rv:{selected_browser.split("/")[1]}) Gecko/{gecko_version} Firefox/{selected_browser.split("/")[1]}'
    else:  # Safari
        webkit_version = f'{random.randint(600, 615)}.{random.randint(1, 36)}'
        user_agent = f'Mozilla/5.0 ({selected_os}) AppleWebKit/{webkit_version} (KHTML, like Gecko) Version/{random.randint(13, 17)}.{random.randint(0, 7)}.{random.randint(1, 10)} Safari/{webkit_version}'
    
    return user_agent

def analyze_result(result_text):
    """分析结果类型：正常、避雷或云黑"""
    if "避雷" in result_text:
        return RESULT_TYPE["AVOID"]
    elif "云黑" in result_text:
        return RESULT_TYPE["CLOUD_BLACK"]
    else:
        return RESULT_TYPE["NORMAL"]

def extract_result(html_content):
    """从HTML中提取查询结果"""
    try:
        # 使用正则表达式提取结果
        pattern = r'<center><a class="BiaoTi">---------查询结果---------</a></center>\s+<center><br>(.*?)<center><br>\s+<center><a class="BiaoTi">------------------------------</a></center>'
        match = re.search(pattern, html_content, re.DOTALL)

        if match:
            result_text = match.group(1).strip()
            # 进一步处理结果
            results = result_text.split('<br>')
            processed_results = []

            for result in results:
                if result.strip():
                    # 移除HTML标签
                    clean_result = re.sub(r'<.*?>', '', result)
                    processed_results.append(clean_result.strip())

            return processed_results
        else:
            logger.warning("未在HTML中找到查询结果")
            return []
    except Exception as e:
        logger.error(f"提取查询结果时出错: {e}")
        return []

def generate_random_qq():
    """生成6位到12位随机QQ号码"""
    # 随机选择位数 (6-12位)
    length = random.randint(MIN_QQ_LENGTH, MAX_QQ_LENGTH)

    # 生成对应位数的随机QQ号码
    if length == MIN_QQ_LENGTH:
        # 对于6位QQ，确保第一位不为0
        return str(random.randint(10**(length-1), 10**length - 1))
    else:
        # 对于其他位数，可以使用完整范围
        return str(random.randint(10**(length-1), 10**length - 1))

def generate_qq_list(size):
    """生成指定数量的随机QQ号码列表"""
    return [generate_random_qq() for _ in range(size)]

def initialize_excel_file():
    """初始化Excel文件，如果不存在则创建"""
    if not os.path.exists(EXCEL_FILENAME):
        # 创建带有表头的空DataFrame
        columns = ["qq", "result", "result_type", "ip_used", "time"]
        df = pd.DataFrame(columns=columns)
        # 保存到Excel
        df.to_excel(EXCEL_FILENAME, index=False)
        logger.info(f"创建了新的Excel文件: {EXCEL_FILENAME}")

def append_results_to_excel(new_results):
    """将新结果追加到Excel文件中"""
    try:
        # 确保Excel文件存在
        initialize_excel_file()

        # 读取现有的Excel文件
        if os.path.getsize(EXCEL_FILENAME) > 0:  # 确保文件不是空的
            existing_df = pd.read_excel(EXCEL_FILENAME)
        else:
            # 如果文件是空的，创建一个带有表头的空DataFrame
            existing_df = pd.DataFrame(columns=["qq", "result", "result_type", "ip_used", "time"])

        # 创建包含新结果的DataFrame
        new_df = pd.DataFrame(new_results)

        # 合并两个DataFrame
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)

        # 保存回Excel文件
        combined_df.to_excel(EXCEL_FILENAME, index=False)

        logger.info(f"已将 {len(new_results)} 条新结果追加到 {EXCEL_FILENAME}")
    except Exception as e:
        logger.error(f"将结果追加到Excel文件时出错: {e}")

def query_qq_numbers(qq_list, max_retries=3):
    """查询QQ号码"""
    retry_count = 0

    while retry_count < max_retries:
        try:
            # 检查是否需要切换代理
            if time.time() - last_proxy_change_time > 45:
                logger.info("已超过45秒，切换代理...")
                if not change_proxy():
                    logger.error("无法切换到新的代理，程序将终止")
                    sys.exit(1)

            # 获取最新代理
            if not current_remote_proxy["host"] or not current_remote_proxy["port"]:
                if not change_proxy():
                    logger.error("无法获取代理，程序将终止")
                    sys.exit(1)

            # 准备代理
            proxies = {
                'http': f'http://{AUTH_KEY}:{PASSWORD}@{current_remote_proxy["host"]}:{current_remote_proxy["port"]}',
                'https': f'http://{AUTH_KEY}:{PASSWORD}@{current_remote_proxy["host"]}:{current_remote_proxy["port"]}'
            }

            # 准备完全随机的请求头，避免任何可能的个人信息
            def get_random_accept_language():
                """生成随机的Accept-Language头"""
                languages = [
                    'zh-CN,zh;q=0.9,en;q=0.8', 
                    'en-US,en;q=0.9',
                    'en-GB,en;q=0.9',
                    'fr-FR,fr;q=0.9,en;q=0.8',
                    'de-DE,de;q=0.9,en;q=0.8',
                    'ja-JP,ja;q=0.9,en;q=0.8',
                    'ru-RU,ru;q=0.9,en;q=0.8',
                    'es-ES,es;q=0.9,en;q=0.8',
                    'it-IT,it;q=0.9,en;q=0.8',
                    'ko-KR,ko;q=0.9,en;q=0.8',
                    'ar-SA,ar;q=0.9,en;q=0.8'
                ]
                return random.choice(languages)
            
            # 随机生成referer，有时不发送
            possible_referers = [
                TARGET_SITE["url"],
                TARGET_SITE["referer"],
                "https://www.google.com/",
                "https://www.bing.com/",
                "https://www.baidu.com/",
                None  # 有时不发送referer
            ]
            referer = random.choice(possible_referers)
            
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'accept-language': get_random_accept_language(),
                'content-type': 'application/x-www-form-urlencoded',
                'user-agent': get_random_user_agent(),
                'cache-control': random.choice(['max-age=0', 'no-cache', 'no-store']),
                'upgrade-insecure-requests': '1',
                'sec-fetch-dest': random.choice(['document', 'empty']),
                'sec-fetch-mode': random.choice(['navigate', 'cors']),
                'sec-fetch-site': random.choice(['same-origin', 'same-site', 'cross-site']),
                'dnt': random.choice(['0', '1']),  # Do Not Track
            }
            
            # 随机添加origin
            if random.random() > 0.3:  # 70%的概率添加origin
                headers['origin'] = TARGET_SITE["url"]
                
            # 随机添加referer
            if referer:
                headers['referer'] = referer
            
            # 生成完全随机的cookies以防止跟踪
            def generate_random_string(length):
                """生成指定长度的随机字符串"""
                chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                return ''.join(random.choice(chars) for _ in range(length))
            
            # 生成随机的时间戳，略微偏离当前时间，以防时间关联
            random_time = int(time.time()) - random.randint(1000, 100000)
            
            cookies = {
                # 使用随机生成的值替代所有固定值
                'Hm_lvt_random': str(random_time),
                'Hm_lpvt_random': str(random_time + random.randint(10, 1000)),
                'HMACCOUNT_' + generate_random_string(8): generate_random_string(16),
                'session': generate_random_string(24)
            }

            # 准备数据
            qq_str = '\r\n'.join(qq_list)
            data = {
                'qq': qq_str
            }

            # 发送请求
            logger.info(f"正在查询QQ号码: {qq_list}")
            try:
                response = requests.post(
                    TARGET_SITE["api_url"],
                    headers=headers,
                    cookies=cookies,
                    data=data,
                    proxies=proxies,
                    timeout=30,  # 添加超时设置
                    verify=False
                )
            except requests.exceptions.RequestException as e:
                logger.error(f"请求失败: {e}")
                logger.info(f"切换代理并重试，这是第 {retry_count+1}/{max_retries} 次重试")
                # 切换代理
                change_proxy()
                retry_count += 1
                # 如果未达到最大重试次数，则继续重试
                if retry_count < max_retries:
                    continue
                else:
                    logger.error(f"已达到最大重试次数 {max_retries}，无法获取结果")
                    return []
            
            # 检查响应
            if response.status_code == 200:
                logger.info("请求成功，正在提取结果...")
                results = extract_result(response.text)
                
                # 检查结果是否为空或长度与QQ列表不匹配，如果是则可能是代理问题
                if not results or len(results) != len(qq_list):
                    logger.warning(f"获取的结果数量与QQ列表不匹配: {len(results)} vs {len(qq_list)}，将重试")
                    # 切换代理
                    change_proxy()
                    retry_count += 1
                    # 如果未达到最大重试次数，则继续重试
                    if retry_count < max_retries:
                        continue
                    else:
                        logger.error(f"已达到最大重试次数 {max_retries}，使用已获取的结果")
                
                logger.info(f"提取到结果: {results}")
                
                # 记录结果和使用的IP信息
                current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                batch_results = []
                
                for i, qq in enumerate(qq_list):
                    result_text = results[i] if i < len(results) else "未获取到结果"
                    # 分析结果类型
                    result_type = analyze_result(result_text)
                    
                    # 记录结果
                    result_item = {
                        "qq": qq,
                        "result": result_text,
                        "result_type": result_type,
                        "ip_used": current_remote_proxy["ip_info"],
                        "time": current_time
                    }
                    
                    # 添加到全局结果和批次结果
                    query_results.append(result_item)
                    batch_results.append(result_item)
                
                # 立即将本批次结果追加到Excel文件
                append_results_to_excel(batch_results)
                
                return results
            else:
                logger.error(f"请求失败，状态码: {response.status_code}")
                # 如果状态码不是200，可能是代理问题，切换代理并重试
                change_proxy()
                retry_count += 1
                # 如果未达到最大重试次数，则继续重试
                if retry_count < max_retries:
                    continue
                else:
                    logger.error(f"已达到最大重试次数 {max_retries}，无法获取结果")
                    return []
        
        except Exception as e:
            logger.error(f"查询QQ号码时出错: {e}")
            # 切换代理
            change_proxy()
            retry_count += 1
            # 如果未达到最大重试次数，则继续重试
            if retry_count < max_retries:
                continue
            else:
                logger.error(f"已达到最大重试次数 {max_retries}，无法获取结果")
                return []
    
    # 如果所有重试都失败
    return []

def save_results_to_file(results, filename="qq_results.txt", max_file_size_mb=10):
    """保存结果到文件，只保存避雷和云黑类型的结果，文件大小超过限制时创建新文件"""
    try:
        # 检查文件是否存在及大小
        new_file = not os.path.exists(filename)
        file_counter = 1
        base_filename, ext = os.path.splitext(filename)
        current_filename = filename
        
        # 如果文件存在且大小超过限制，创建新文件
        while os.path.exists(current_filename) and os.path.getsize(current_filename) > max_file_size_mb * 1024 * 1024:
            file_counter += 1
            current_filename = f"{base_filename}_{file_counter}{ext}"
            logger.info(f"文件大小超过{max_file_size_mb}MB，创建新文件: {current_filename}")
        
        filtered_results = []
        for result in results:
            # 判断是否是字符串，如果是则进行简单判断
            if isinstance(result, str):
                if "避雷" in result or "云黑" in result:
                    filtered_results.append(result)
            # 如果是从查询结果中直接获取的字典对象
            elif isinstance(result, dict) and "result_type" in result:
                if result["result_type"] in [RESULT_TYPE["AVOID"], RESULT_TYPE["CLOUD_BLACK"]]:
                    # 格式化为字符串保存
                    formatted_result = f"QQ: {result['qq']}, 结果: {result['result']}, 类型: {result['result_type']}, IP: {result['ip_used']}, 时间: {result['time']}"
                    filtered_results.append(formatted_result)
        
        # 如果没有符合条件的结果，直接返回
        if not filtered_results:
            logger.info("没有避雷或云黑类型的结果需要保存")
            return
        
        # 写入文件
        with open(current_filename, "a", encoding="utf-8") as f:
            for result in filtered_results:
                f.write(f"{result}\n")
        
        logger.info(f"已将 {len(filtered_results)} 条避雷/云黑结果保存到 {current_filename}")
    except Exception as e:
        logger.error(f"保存结果到文件时出错: {e}")

def save_results_to_excel(filename=EXCEL_FILENAME):
    """将所有结果保存到Excel文件（仅用于最终汇总）"""
    try:
        df = pd.DataFrame(query_results)
        df.to_excel(filename, index=False)
        logger.info(f"所有结果已保存到Excel文件: {filename}")
    except Exception as e:
        logger.error(f"保存结果到Excel文件时出错: {e}")

def batch_query(qq_numbers, batch_size=None):
    """批量查询QQ号码"""
    if batch_size is None:
        # 使用随机批量大小 (300-500)
        batch_size = random.randint(MIN_BATCH_SIZE, MAX_BATCH_SIZE)
        logger.info(f"设置批量查询大小为: {batch_size}")
        
    all_results = []
    batches = [qq_numbers[i:i+batch_size] for i in range(0, len(qq_numbers), batch_size)]
    
    for i, batch in enumerate(batches):
        logger.info(f"正在处理第 {i+1}/{len(batches)} 批 (共 {len(batch)} 个QQ)...")
        results = query_qq_numbers(batch)
        all_results.extend(results)
        
        # 立即保存本批次特殊结果
        save_results_to_file(results, max_file_size_mb=20)
        
        # 如果不是最后一批，添加随机延迟
        if i < len(batches) - 1:
            delay = random.uniform(MIN_DELAY, MAX_DELAY)
            logger.info(f"请求完成，等待 {delay:.1f} 秒...")
            time.sleep(delay)
    
    return all_results

def generate_qq_range(start_qq, end_qq, count):
    """生成指定范围内的随机QQ号码"""
    if start_qq > end_qq:
        start_qq, end_qq = end_qq, start_qq
    
    # 如果范围内的数量少于请求的数量，返回整个范围
    range_size = end_qq - start_qq + 1
    if range_size <= count:
        return [str(qq) for qq in range(start_qq, end_qq + 1)]
    
    # 否则随机选择count个不重复的数字
    return [str(qq) for qq in random.sample(range(start_qq, end_qq + 1), count)]

def save_checkpoint():
    """保存当前查询进度到文件"""
    try:
        with open(CHECKPOINT_FILE, 'wb') as f:
            pickle.dump(query_progress, f)
        logger.info(f"当前查询进度已保存至 {CHECKPOINT_FILE}")
    except Exception as e:
        logger.error(f"保存查询进度失败: {e}")

def load_checkpoint():
    """从文件加载查询进度"""
    global query_progress
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'rb') as f:
                query_progress = pickle.load(f)
            
            current_range_index = query_progress["current_range_index"]
            current_position = query_progress["current_position"]
            current_range = query_progress["ranges"][current_range_index]
            
            logger.info(f"已恢复查询进度: 当前查询第 {current_range_index+1}/{len(query_progress['ranges'])} 个范围")
            logger.info(f"QQ范围: {current_range[0]}-{current_range[1]}, 当前位置: {current_position}")
            return True
        except Exception as e:
            logger.error(f"加载查询进度失败: {e}")
    
    logger.info("未找到进度文件或无法加载，将从头开始查询")
    return False

def get_next_qq_batch(batch_size):
    """获取下一批要查询的QQ号码"""
    global query_progress
    
    if query_progress["current_range_index"] >= len(query_progress["ranges"]):
        logger.info("所有范围都已查询完毕")
        return []
    
    current_range = query_progress["ranges"][query_progress["current_range_index"]]
    start_position = max(current_range[0], query_progress["current_position"])
    end_position = current_range[1]
    
    # 如果当前范围已经查询完毕，移动到下一个范围
    if start_position > end_position or current_range[2]:  # 已处理标志为True
        query_progress["current_range_index"] += 1
        if query_progress["current_range_index"] < len(query_progress["ranges"]):
            query_progress["current_position"] = query_progress["ranges"][query_progress["current_range_index"]][0]
            return get_next_qq_batch(batch_size)
        else:
            logger.info("所有范围都已查询完毕")
            return []
    
    # 确定本批次的结束位置
    batch_end = min(start_position + batch_size - 1, end_position)
    
    # 生成QQ号码列表
    qq_list = [str(qq) for qq in range(start_position, batch_end + 1)]
    
    # 更新进度
    query_progress["current_position"] = batch_end + 1
    
    # 如果当前范围已查询完毕，标记为已处理
    if batch_end >= end_position:
        query_progress["ranges"][query_progress["current_range_index"]][2] = True
        logger.info(f"范围 {current_range[0]}-{current_range[1]} 已查询完毕")
    
    logger.info(f"获取QQ批次: {start_position}-{batch_end} (共 {len(qq_list)} 个)")
    return qq_list

def sequential_query(batch_size=None):
    """按照顺序批量查询QQ号码"""
    if batch_size is None:
        # 使用随机批量大小 (300-500)
        batch_size = random.randint(MIN_BATCH_SIZE, MAX_BATCH_SIZE)
    
    all_results = []
    batch_count = 0
    
    # 恢复查询进度
    load_checkpoint()
    
    while True:
        # 获取下一批QQ号码
        qq_batch = get_next_qq_batch(batch_size)
        
        # 如果没有更多QQ号码，结束查询
        if not qq_batch:
            logger.info("没有更多QQ号码需要查询")
            break
        
        logger.info(f"正在处理第 {batch_count+1} 批 (共 {len(qq_batch)} 个QQ)...")
        results = query_qq_numbers(qq_batch)
        all_results.extend(results)
        
        # 立即保存本批次特殊结果
        save_results_to_file(results, max_file_size_mb=20)
        
        batch_count += 1
        
        # 定期保存进度
        if batch_count % SAVE_CHECKPOINT_INTERVAL == 0:
            save_checkpoint()
        
        # 随机延迟
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        logger.info(f"请求完成，等待 {delay:.1f} 秒...")
        time.sleep(delay)
    
    # 保存最终进度
    save_checkpoint()
    return all_results

def main():
    """主函数"""
    try:
        # 初始化Excel文件
        initialize_excel_file()
        
        # 启动本地代理服务器
        proxy_server = start_local_proxy_server()
        if not proxy_server:
            logger.error("无法启动本地代理服务器，爬取终止")
            return
        
        # 获取初始代理 - 如果无法获取，程序会自动终止
        proxy_host, proxy_port = get_working_proxy()
        
        if proxy_host and proxy_port:
            current_remote_proxy["host"] = proxy_host
            current_remote_proxy["port"] = proxy_port
            
            # 获取当前IP信息
            ip_info = get_current_ip_info(proxy_host, proxy_port)
            current_remote_proxy["ip_info"] = ip_info
            
            global last_proxy_change_time
            last_proxy_change_time = time.time()
            logger.info(f"初始代理设置为: {proxy_host}:{proxy_port}")
            logger.info(f"当前IP信息: {ip_info}")
        else:
            logger.error("无法获取可用代理，程序终止")
            sys.exit(1)
        
        # 确定批量大小
        batch_size = random.randint(MIN_BATCH_SIZE, MAX_BATCH_SIZE)
        logger.info(f"设置批量查询大小为: {batch_size}")
        
        # 测试模式开关 (False = 全范围查询模式)
        test_mode = False
        
        if test_mode:
            # 测试模式：使用一些特定样例和随机QQ
            qq_numbers = [
                "",  # 避雷示例
                "",  # 云黑示例
            ]
            
            # 添加一些不同位数的随机QQ用于测试
            for length in range(MIN_QQ_LENGTH, MAX_QQ_LENGTH + 1):
                min_val = 10**(length-1)
                max_val = 10**length - 1
                # 每个位数生成2个随机QQ
                for _ in range(2):
                    qq_numbers.append(str(random.randint(min_val, max_val)))
            
            logger.info(f"生成了 {len(qq_numbers)} 个测试用QQ号码")
            
            # 批量查询
            logger.info("开始批量查询QQ号码...")
            results = batch_query(qq_numbers, batch_size)
        else:
            # 系统性连续查询模式
            logger.info("开始系统性连续查询所有QQ号码范围...")
            results = sequential_query(batch_size)
        
        # 保存结果到文本文件，设置文件大小限制为20MB
        save_results_to_file(results, max_file_size_mb=20)
        
        # 最终汇总保存结果到Excel
        save_results_to_excel()
        
        logger.info("查询完成，结果已保存")
    
    except KeyboardInterrupt:
        logger.info("用户中断程序")
        save_checkpoint()  # 保存当前进度
        logger.info("已保存当前查询进度，可稍后继续")
    except Exception as e:
        logger.error(f"程序执行时出错: {e}")
        save_checkpoint()  # 保存当前进度
    
    finally:
        # 保存最终结果到Excel
        try:
            save_results_to_excel()
        except Exception as e:
            logger.error(f"保存最终结果时出错: {e}")
            
        # 尝试停止代理服务器
        if 'proxy_server' in locals() and proxy_server:
            proxy_server.shutdown()
            logger.info("代理服务器已关闭")

if __name__ == "__main__":
    logger.info("程序开始执行...")
    main()
    logger.info("程序执行完毕") 