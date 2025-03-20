#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 代理配置
PROXY_API_URL = "https://your-proxy-api-url"
AUTH_KEY = "your-auth-key"  # 代理认证用户名
PASSWORD = "your-password"  # 代理认证密码
LOCAL_PROXY_PORT = 8899  # 本地代理端口
MAX_PROXY_RETRIES = 3  # 最大代理重试次数

# 目标网站配置
TARGET_SITE = {
    "url": "https://fz.qimeng.fun",
    "api_url": "https://fz.qimeng.fun/",
    "referer": "https://fz.qimeng.fun/"
}

# IP检查配置
IP_CHECK_URL = "http://myip.ipip.net/"

# 批量查询配置
MIN_BATCH_SIZE = 300  # 每批最少查询数量
MAX_BATCH_SIZE = 500  # 每批最多查询数量
MIN_DELAY = 3  # 查询之间最小延迟秒数
MAX_DELAY = 5  # 查询之间最大延迟秒数

# Excel文件名
EXCEL_FILENAME = "qq_results.xlsx"

# 断点续传配置
CHECKPOINT_FILE = "checkpoint.pkl"  # 保存查询进度的文件
SAVE_CHECKPOINT_INTERVAL = 5  # 每查询多少批保存一次进度

# QQ号码范围
MIN_QQ_LENGTH = 6  # 最小QQ位数
MAX_QQ_LENGTH = 12  # 最大QQ位数
MIN_QQ = 10 ** (MIN_QQ_LENGTH - 1)  # 最小QQ号码值 (100000)
MAX_QQ = 10 ** MAX_QQ_LENGTH - 1  # 最大QQ号码值 (999999999999)

# 查询范围配置
QUERY_RANGES = [
    # 每个范围表示为: [开始QQ号码, 结束QQ号码, 已处理标志]
    [100000, 999999, False],  # 6位QQ
    [1000000, 9999999, False],  # 7位QQ
    [10000000, 99999999, False],  # 8位QQ
    [100000000, 999999999, False],  # 9位QQ
    [1000000000, 9999999999, False],  # 10位QQ
    [10000000000, 99999999999, False],  # 11位QQ
    [100000000000, 999999999999, False]  # 12位QQ
]

# 结果类型枚举
RESULT_TYPE = {
    "NORMAL": "正常",
    "AVOID": "避雷",
    "CLOUD_BLACK": "云黑"
} 