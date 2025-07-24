# CA (Chip Authentication) 认证流程详解

## 概述
CA认证是电子护照中用于验证芯片真实性的机制，通过密钥协商建立新的安全通道。

## 前置条件
1. 已通过BAC或PACE建立初始安全通道
2. 已读取DG14（包含CA公钥信息）

## 详细流程

### 1. 解析DG14
```
DG14 (SecurityInfos) 包含：
├── ChipAuthenticationInfo (可选)
│   ├── OID (算法标识)
│   ├── Version
│   └── KeyId (可选)
└── ChipAuthenticationPublicKeyInfo
    ├── OID (公钥类型)
    ├── SubjectPublicKeyInfo (DER编码的公钥)
    └── KeyId (可选)
```

### 2. 生成临时密钥对
基于DG14中的公钥参数生成相同类型的密钥对：
- 如果是DH公钥 → 生成DH密钥对
- 如果是ECDH公钥 → 生成ECDH密钥对

### 3. 发送公钥到护照

#### 3.1 DESede算法情况
使用MSE Set KAT命令：
```
CLA INS P1  P2  Lc  Data
00  22  41  A6  XX  91 LL [PublicKey] 84 LL [KeyId]
```
- Tag 0x91: 公钥数据
- Tag 0x84: 密钥ID（可选）

#### 3.2 AES算法情况
分两步：
1. MSE Set AT Internal Auth:
```
CLA INS P1  P2  Lc  Data
00  22  41  A4  XX  80 LL [OID] 84 LL [KeyId]
```

2. General Authenticate (可能需要命令链):
```
CLA INS P1  P2  Lc  Data
00  86  00  00  XX  7C LL [80 LL PublicKey]
```

### 4. 计算共享密钥
使用DH/ECDH算法：
- 终端：使用自己的私钥 + 护照公钥
- 护照：使用自己的私钥 + 终端公钥
- 双方计算出相同的共享密钥

### 5. 派生会话密钥
使用KDF（密钥派生函数）：
```
KsEnc = KDF(SharedSecret || 0x00000001)  // 加密密钥
KsMac = KDF(SharedSecret || 0x00000002)  // MAC密钥

其中KDF定义为：
- 3DES/AES-128: SHA-1(input)[0:keyLength]
- AES-192/256: SHA-256(input)[0:keyLength]
```

### 6. 重启安全消息
使用新的会话密钥建立安全通道：
- SSC初始化为0
- 根据算法选择DES或AES安全消息模式

## 关键数据结构

### ChipAuthenticationInfo OIDs
```
DH + 3DES:    0.4.0.127.0.7.2.2.3.1.1
DH + AES-128: 0.4.0.127.0.7.2.2.3.1.2
DH + AES-192: 0.4.0.127.0.7.2.2.3.1.3
DH + AES-256: 0.4.0.127.0.7.2.2.3.1.4

ECDH + 3DES:    0.4.0.127.0.7.2.2.3.2.1
ECDH + AES-128: 0.4.0.127.0.7.2.2.3.2.2
ECDH + AES-192: 0.4.0.127.0.7.2.2.3.2.3
ECDH + AES-256: 0.4.0.127.0.7.2.2.3.2.4
```

### 公钥类型OIDs
```
DH公钥:   0.4.0.127.0.7.2.2.1.1
ECDH公钥: 0.4.0.127.0.7.2.2.1.2
```

## 错误处理
1. 如果CA失败，需要重新建立BAC连接
2. 可能有多个公钥，需要逐个尝试
3. 某些护照可能缺少ChipAuthenticationInfo，需要从公钥类型推断算法

## 安全考虑
- CA提供前向安全性
- 每次会话使用不同的临时密钥
- 防止密钥泄露影响历史通信