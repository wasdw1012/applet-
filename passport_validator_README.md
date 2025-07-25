# 护照证书链验证脚本使用说明

## 概述
本脚本用于验证电子护照中的证书链结构，包括CSCA证书、DSC证书、DG14、DG15、AA私钥和CA私钥S值的完整性验证。

## 安装依赖

```bash
pip install cryptography
pip install pyasn1
pip install pyasn1-modules
```

## 文件准备

脚本会自动搜索当前目录中具有特定后缀的文件。请确保以下文件都在脚本所在目录中：

1. **CSCA证书** - 文件后缀为 `_cert.der`，文件名包含'csca'（如：csca_cert.der）
2. **DSC证书** - 文件后缀为 `_cert.der`，文件名不包含'csca'（如：dsc_cert.der）
3. **DG14数据** - 文件后缀为 `dg14.bin`（如：passport_dg14.bin）
4. **DG15数据** - 文件后缀为 `dg15.bin`（如：passport_dg15.bin）
5. **AA私钥** - 文件后缀为 `_private.der`（如：aa_private.der）
6. **CA私钥S值** - 文件后缀为 `_s_value.bin`（如：ca_s_value.bin）

**注意**：文件名前缀可以是任意的，脚本会根据后缀自动识别文件类型。

## 运行脚本

```bash
python passport_certificate_validator.py
```

## 验证内容

### 1. CSCA证书验证
- 证书格式和版本
- 自签名验证
- 有效期检查
- 必要扩展字段验证（BasicConstraints, KeyUsage）
- Subject Key Identifier提取

### 2. DSC证书验证
- 证书格式和版本
- CSCA签发验证
- AKI/SKI匹配验证
- 证书链完整性
- 有效期检查

### 3. DG14验证
- ASN.1结构解析
- 支持的协议识别
- Chip Authentication协议检查
- Terminal Authentication协议检查
- PACE协议检查

### 4. DG15验证
- Active Authentication公钥解析
- RSA/ECDSA密钥类型识别
- RSA1024兼容性验证

### 5. AA密钥对验证
- 私钥格式验证
- RSA1024长度验证（避免前导0字节问题）
- 公私钥配对测试
- 签名/验签功能测试

### 6. CA私钥S值验证
- 二进制格式解析
- 数学属性验证
- 椭圆曲线参数推断
- 与DG14协议的匹配性

### 7. 信任链闭环验证
- 完整信任链构建
- 各组件间关系验证
- 链接完整性检查

## 输出报告

脚本运行完成后会生成两个输出：

1. **控制台输出** - 实时显示验证进度和结果
2. **报告文件** - `passport_validation_report_YYYYMMDD_HHMMSS.txt`

报告包含以下内容：
- 每个组件的详细验证结果
- 检测到的错误和警告
- 信任链结构图
- 详细的验证日志

## 支持的协议

脚本支持以下ICAO标准协议：

### Chip Authentication (CA)
- id-CA-DH-3DES-CBC-CBC
- id-CA-DH-AES-CBC-CMAC-128/192/256
- id-CA-ECDH-3DES-CBC-CBC
- id-CA-ECDH-AES-CBC-CMAC-128/192/256

### Terminal Authentication (TA)
- id-TA-RSA-v1-5-SHA-1/224/256/384/512
- id-TA-RSA-PSS-SHA-1/256
- id-TA-ECDSA-SHA-1/224/256/384/512

### PACE
- id-PACE-DH-GM-3DES-CBC-CBC
- id-PACE-DH-GM-AES-CBC-CMAC-128
- id-PACE-ECDH-GM-3DES-CBC-CBC
- id-PACE-ECDH-GM-AES-CBC-CMAC-128
- id-PACE-ECDH-CAM-AES-CBC-CMAC-128

## 注意事项

1. **OpenSSL路径**：脚本硬编码了Windows下的OpenSSL路径（`C:\Program Files\OpenSSL-Win64\bin\openssl.exe`）。如果您的OpenSSL安装在其他位置，请修改脚本中的`OPENSSL_PATH`变量。

2. **文件格式**：所有证书和密钥文件必须是DER格式，不支持PEM格式。

3. **AA私钥长度**：脚本会特别检查AA私钥是否为RSA1024，这是为了避免RSA2048可能导致的前导0字节兼容性问题。

4. **错误处理**：脚本会详细记录每个验证步骤的结果，即使某个组件验证失败，也会继续验证其他组件。

## 故障排除

1. **文件不存在错误**：确保所有必需的文件都在正确的位置，文件名完全匹配。

2. **证书解析错误**：确保证书文件是有效的DER格式，可以使用OpenSSL命令检查：
   ```bash
   openssl x509 -in csca_cert.der -inform DER -text -noout
   ```

3. **密钥不匹配**：如果AA密钥对验证失败，请确保aa_private.der与dg15.bin中的公钥确实是一对。

4. **S值验证失败**：CA私钥S值应该是一个有效的椭圆曲线标量值，通常是32字节（P-256）或48字节（P-384）。