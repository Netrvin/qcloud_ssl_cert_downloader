# qcloud_ssl_cert_downloader

本脚本用于从腾讯云SSL证书功能中，下载指定域名的生效的SSL证书，并保存到指定文件路径  
注：当前仅提取Nginx所需证书文件，其他Web服务请适当修改代码

## 前置准备

### Python环境
安装Python3和相关依赖
```bash
pip3 install requests tencentcloud-sdk-python-common==3.0.1421 tencentcloud-sdk-python-ssl==3.0.1420
``` 

### 密钥申请
在访问管理中，添加自定义策略，JSON如下：
```json
{
    "statement": [
        {
            "action": [
                "ssl:DescribeCertificates",
                "ssl:DownloadCertificate"
            ],
            "effect": "allow",
            "resource": [
                "*"
            ]
        }
    ],
    "version": "2.0"
}
```

然后新建用户，关联刚才新建的策略，记录生成的`SecretId`和`SecretKey`

### 配置
修改`config.json`，填写API密钥，并在NeededCerts中填写需要下载的每个证书信息：证书包含的域名、保存路径
```json
{
    "SecretId": "",
    "SecretKey": "",
    "NeededCerts": [
        {
            "Domains": ["example.com", "www.example.com"],
            "CertSavePath": "/etc/nginx/ssl/example.com.crt",
            "KeySavePath": "/etc/nginx/ssl/example.com.key"
        }
    ]
}
```

## 运行

```bash
python3 download.py
```

记得重载/重启Web服务器以加载最新的SSL证书