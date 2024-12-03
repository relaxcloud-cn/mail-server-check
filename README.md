# 邮件服务器安全检查工具

一个用于检查邮件服务器安全配置并识别潜在漏洞的综合工具。

## 功能特性

- 域名SPF记录验证
- DMARC策略验证
- MX记录分析
- SMTP服务器安全评估
- 用户枚举检测
- 便捷的Web操作界面
- 详细的安全报告生成

## 环境要求

- Python 3.6+
- nmap
- 现代浏览器

## 安装说明

1. 克隆仓库：

```bash
git clone [仓库地址]
cd mail_server_check
```

2. 安装系统依赖：

```bash
apt install nmap
```

3. 安装Python依赖：

```bash
pip3 install -r requirements.txt
```

## 使用说明

### Web界面

1. 启动Web服务器：

```bash
cd src
python3 app.py
```

2. 打开浏览器访问 `http://localhost:5000`

3. 输入要检查的域名并点击"检查"

<div align=center> <img src=".img/2024-12-03-10-12-31.png" width = 80%/> </div>

### 命令行界面

邮件banner收集

```bash
usage: spoofcheck.py recon [-h] [-d DOMAIN] [-dL DOMAINS] [-b] [-f FILENAME]

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        域名
  -dL DOMAINS, --domains DOMAINS
                        域名文件
  -b, --banner          获取banner
  -f FILENAME, --filename FILENAME
                        输出文件名
```

邮件域名安全检查

```bash
usage: spoofcheck.py check [-h] [-d DOMAIN] [-dL DOMAINS] [-u] [-s]

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        域名
  -dL DOMAINS, --domains DOMAINS
                        域名文件
  -u, --enumerate-users
                        枚举用户
  -s, --summary         生成摘要
```

### SDK使用示例

```python
from spoofcheck import SpoofCheck

spoofcheck = SpoofCheck()
res = spoofcheck.check("example.com")
res.info()
```

## 安全报告

工具生成的详细安全报告包括：

- 风险等级评估
- 漏洞详情
- 发现的证据
- 修复建议

报告存储在 `reports` 目录中。

## Docker支持

使用Docker构建和运行：

```bash
docker build -t mail-server-check .
docker run -p 5000:5000 mail-server-check
```

## 参与贡献

1. Fork本仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m '添加某个特性'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 发起Pull Request

## 开源许可

BSD 3-Clause License

## 致谢

- [checkdmarc](https://github.com/domainaware/checkdmarc) - DMARC验证
- [pwntools](https://github.com/Gallopsled/pwntools) - 网络操作
