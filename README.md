# 云黑账号查询工具

这是一个用于批量查询云黑账号QQ号码信息的工具，使用代理API进行查询。

## 配置文件

所有配置项已经移到 `config.py` 文件中，您可以根据需要修改配置。为了保护敏感信息，此文件已被添加到 `.gitignore` 中。

请复制 `config.example.py` 为 `config.py`，并填入您的实际配置信息：

```bash
cp config.example.py config.py
```

主要配置项包括：

### 代理配置
- `PROXY_API_URL`: 代理API地址
- `AUTH_KEY`: 代理认证用户名
- `PASSWORD`: 代理认证密码
- `LOCAL_PROXY_PORT`: 本地代理端口
- `MAX_PROXY_RETRIES`: 最大代理重试次数

### 目标网站配置
- `TARGET_SITE`: 包含目标网站的URL、API地址和引用页 
- 当前配置中的 'https://fz.qimeng.fun' 仅为示例，不代表使用网站，您需要根据实际情况修改！

### IP检查配置
- `IP_CHECK_URL`: 用于检查当前IP的服务

### 批量查询配置
- `MIN_BATCH_SIZE`: 每批最少查询数量
- `MAX_BATCH_SIZE`: 每批最多查询数量
- `MIN_DELAY`: 查询之间最小延迟秒数
- `MAX_DELAY`: 查询之间最大延迟秒数

### 文件和保存配置
- `EXCEL_FILENAME`: Excel文件名
- `CHECKPOINT_FILE`: 保存查询进度的文件
- `SAVE_CHECKPOINT_INTERVAL`: 每查询多少批保存一次进度

### QQ号码范围配置
- `MIN_QQ_LENGTH`: 最小QQ位数
- `MAX_QQ_LENGTH`: 最大QQ位数
- `QUERY_RANGES`: 查询范围配置

## 使用方法

1. 复制并配置 `config.py` 文件
   ```bash
   cp config.example.py config.py
   ```
   
2. 修改 `config.py` 中的配置，特别是代理配置部分

3. 运行程序开始查询
   ```bash
   python qimeng.py
   ```

## 数据格式

查询结果将保存为Excel文件，每行包含以下字段：
- `qq`: QQ号码
- `result`: 查询结果文本
- `result_type`: 结果类型（正常、避雷、云黑）
- `ip_used`: 使用的代理IP
- `time`: 查询时间

## 注意事项

- 程序会自动处理代理切换
- 支持断点续传，可以在中断后继续进行查询
- 使用前请确保代理配置正确

## 项目介绍

查询工具是一个用于批量查询云黑账号QQ信息的Python脚本。它通过代理服务器发送请求到查询平台，获取云黑账号的相关信息，并将结果保存到Excel文件中。该工具支持以下主要功能：

- 自动切换代理IP，防止IP被封禁
- 批量查询QQ号码（支持6-12位的QQ号）
- 结果分析与分类（正常、避雷、云黑）
- 查询结果保存到Excel文件
- 断点续传，支持中断后继续查询
- 系统性查询模式和测试模式
- 自动重试机制，处理代理超时和请求失败的情况

## 安装依赖

在使用本工具前，请确保已安装以下Python依赖包：

```bash
pip install requests pandas beautifulsoup4 urllib3
```

## 使用方法

1. **启动程序**

```bash
python qimeng.py
```

2. **运行模式**

在代码中设置`test_mode`变量来选择运行模式：
- `test_mode = True`: 测试模式，将查询一小批预设和随机的QQ号码
- `test_mode = False`: 系统性连续查询模式，将按顺序查询6-12位的所有QQ号码范围

```python
# 测试模式开关 (False = 全范围查询模式)
test_mode = False
```

3. **查询结果**

查询结果将保存在`qq_results.xlsx`文件中，包含以下字段：
- `qq`: 查询的QQ号码
- `result`: 查询结果详情
- `result_type`: 结果类型（正常、避雷、云黑）
- `ip_used`: 使用的代理IP信息
- `time`: 查询时间

## 断点续传

程序支持断点续传功能，当程序中断（如按Ctrl+C）时，会自动保存当前的查询进度到`checkpoint.pkl`文件。重新启动程序时，将自动从上次的查询位置继续。

## 主要功能模块

1. **代理管理**
   - `start_local_proxy_server()`: 启动本地代理服务器
   - `get_proxy()`: 获取代理IP
   - `change_proxy()`: 切换代理IP
   - `get_current_ip_info()`: 获取当前IP信息

2. **查询功能**
   - `query_qq_numbers()`: 查询QQ号码，支持自动重试
   - `batch_query()`: 批量查询QQ号码
   - `sequential_query()`: 按顺序批量查询QQ号码

3. **结果处理**
   - `extract_result()`: 从HTML中提取查询结果
   - `analyze_result()`: 分析结果类型
   - `append_results_to_excel()`: 将结果追加到Excel文件

4. **断点续传**
   - `save_checkpoint()`: 保存查询进度
   - `load_checkpoint()`: 加载查询进度
   - `get_next_qq_batch()`: 获取下一批要查询的QQ号码

5. **错误处理与重试**
   - 自动检测请求超时和失败的情况
   - 在代理超时或请求失败时自动切换代理
   - 针对同一批QQ，最多重试3次
   - 检测返回结果与请求QQ数量是否匹配，不匹配则重试

## 注意事项

1. 请确保配置了正确的代理信息，否则程序无法正常运行
2. 系统性连续查询模式可能需要很长时间才能完成，建议使用断点续传功能
3. 程序运行过程中可以随时按Ctrl+C中断，会自动保存当前进度
4. 查询频率过高可能导致IP被临时封禁，请合理设置查询间隔
5. 程序包含自动重试机制，当代理超时或请求失败时会自动切换代理并重试，最多重试3次

## 免责声明

本工具仅供学习和研究使用，请勿用于非法用途。使用本工具产生的任何法律责任由使用者自行承担。 