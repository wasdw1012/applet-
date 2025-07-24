# ICAO 9303 第11部分 - 芯片认证(CA)规范

本文档从ICAO 9303第11部分中提取并整理了芯片认证(Chip Authentication)的核心规范内容。

## 6.2 芯片认证

芯片认证协议是临时静态的Diffie-Hellman密钥协商协议，提供电子机读旅行证件芯片的安全通信和单向认证。

### 主要特点

- 阻止询问语义，因为该协议产生的副本是不可转移的
- 除了电子机读旅行证件芯片的认证，该协议还提供强会话密钥

### 密钥存储要求

静态芯片认证密钥对必须存储在电子机读旅行证件芯片上：
- **私钥**：应被安全存储在电子机读旅行证件芯片的存储器内
- **公钥**：存储在ChipAuthenticationPublicKeyInfo结构的SubjectPublicKeyInfo中

## 6.2.1 协议规范

### 协议步骤

1. **芯片发送公钥**：电子机读旅行证件芯片向终端发送其静态Diffie-Hellman公钥PKIC和域参数DIC

2. **终端生成临时密钥对**：终端生成临时Diffie-Hellman密钥对（SKDH,IFD, PKDH,IFD, DIC）并将临时公钥PKDH,IFD发送给电子机读旅行证件芯片

3. **双方计算共享密钥**：
   - 共享秘密：K = KA(SKIC, PKDH,IFD, DIC) = KA(SKDH,IFD, PKIC, DIC)
   - 派生会话密钥：KSMAC = KDFMAC(K) 和 KSEnc = KDFEnc(K)

### 安全验证

为核验PKIC的真实性，终端应执行被动认证。

## 6.2.2 安全状态

- **成功**：使用派生的会话密钥KSMAC和KSEnc重启安全通讯
- **失败**：使用之前建立的会话密钥（PACE或BAC）继续进行安全通讯

注：被动认证必须和芯片认证结合起来执行。只有在对相应的SOD进行成功认证后，电子机读旅行证件芯片才可被认为是真实的。

## 6.2.3 密码规范

### 6.2.3.1 基于DH的芯片认证

| 客体标识符 | 对称密码 | 密钥长度 | 安全通讯 |
|-----------|---------|---------|----------|
| id-CA-DH-3DES-CBC-CBC | 3DES | 112 | CBC/CBC |
| id-CA-DH-AES-CBC-CMAC-128 | AES | 128 | CBC/CMAC |
| id-CA-DH-AES-CBC-CMAC-192 | AES | 192 | CBC/CMAC |
| id-CA-DH-AES-CBC-CMAC-256 | AES | 256 | CBC/CMAC |

### 6.2.3.2 基于ECDH的芯片认证

| 客体标识符 | 对称密码 | 密钥长度 | 安全通讯 |
|-----------|---------|---------|----------|
| id-CA-ECDH-3DES-CBC-CBC | 3DES | 112 | CBC/CBC |
| id-CA-ECDH-AES-CBC-CMAC-128 | AES | 128 | CBC/CMAC |
| id-CA-ECDH-AES-CBC-CMAC-192 | AES | 192 | CBC/CMAC |
| id-CA-ECDH-AES-CBC-CMAC-256 | AES | 256 | CBC/CMAC |

## 6.2.4 应用协议数据单元

基于使用的对称算法，芯片认证可有两种实现方法：

1. **3DES安全通讯**：使用MSE:Set KAT命令
2. **AES安全通讯**：使用MSE:Set AT + GENERAL AUTHENTICATE命令序列

### 6.2.4.1 使用MSE:Set KAT实现

**命令结构**：
- CLA: 上下文特定
- INS: 0x22 (管理安全环境)
- P1/P2: 0x41A6 (设定用于计算的密钥协商模板)

**数据字段**：
- Tag 0x91: 临时公钥PKDH,IFD（必要）
- Tag 0x84: 私钥引用（有条件，多密钥时需要）

**响应**：
- 0x9000: 正常处理，密钥协商成功
- 0x6A80: 命令数据域的参数不正确（临时公钥验证失败）

### 6.2.4.2 使用MSE:Set AT和GENERAL AUTHENTICATE实现

#### 1. MSE:Set AT

**命令结构**：
- CLA: 上下文特定
- INS: 0x22
- P1/P2: 0x41A4 (设定用于内部认证的认证模版)

**数据字段**：
- Tag 0x80: 密码机制引用（协议OID，省略0x06标识符）
- Tag 0x84: 私钥引用（有条件）

#### 2. GENERAL AUTHENTICATE

**命令结构**：
- CLA: 上下文特定
- INS: 0x86
- P1/P2: 0x0000

**数据字段**：
- Tag 0x7C: 动态认证数据
  - Tag 0x80: 临时公钥

**响应**：
- Tag 0x7C: 动态认证数据（必要）
- 0x9000: 正常处理

## 9.2.5 ChipAuthenticationInfo

ASN.1定义：
```asn1
ChipAuthenticationInfo ::= SEQUENCE {
    protocol OBJECT IDENTIFIER(
        id-CA-DH-3DES-CBC-CBC |
        id-CA-DH-AES-CBC-CMAC-128 |
        id-CA-DH-AES-CBC-CMAC-192 |
        id-CA-DH-AES-CBC-CMAC-256 |
        id-CA-ECDH-3DES-CBC-CBC |
        id-CA-ECDH-AES-CBC-CMAC-128 |
        id-CA-ECDH-AES-CBC-CMAC-192 |
        id-CA-ECDH-AES-CBC-CMAC-256),
    version INTEGER, -- MUST be 1
    keyId INTEGER OPTIONAL
}
```

## 9.2.6 ChipAuthenticationPublicKeyInfo

ASN.1定义：
```asn1
ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
    protocol OBJECT IDENTIFIER(id-PK-DH | id-PK-ECDH),
    chipAuthenticationPublicKey SubjectPublicKeyInfo,
    keyId INTEGER OPTIONAL
}
```

## 9.2.7 芯片认证客体标识符(OID)

```asn1
id-PK OBJECT IDENTIFIER ::= {
    bsi-de protocols(2) smartcard(2) 1
}

id-PK-DH OBJECT IDENTIFIER ::= {id-PK 1}
id-PK-ECDH OBJECT IDENTIFIER ::= {id-PK 2}

id-CA OBJECT IDENTIFIER ::= {
    bsi-de protocols(2) smartcard(2) 3
}

id-CA-DH OBJECT IDENTIFIER ::= {id-CA 1}
id-CA-DH-3DES-CBC-CBC OBJECT IDENTIFIER ::= {id-CA-DH 1}
id-CA-DH-AES-CBC-CMAC-128 OBJECT IDENTIFIER ::= {id-CA-DH 2}
id-CA-DH-AES-CBC-CMAC-192 OBJECT IDENTIFIER ::= {id-CA-DH 3}
id-CA-DH-AES-CBC-CMAC-256 OBJECT IDENTIFIER ::= {id-CA-DH 4}

id-CA-ECDH OBJECT IDENTIFIER ::= {id-CA 2}
id-CA-ECDH-3DES-CBC-CBC OBJECT IDENTIFIER ::= {id-CA-ECDH 1}
id-CA-ECDH-AES-CBC-CMAC-128 OBJECT IDENTIFIER ::= {id-CA-ECDH 2}
id-CA-ECDH-AES-CBC-CMAC-192 OBJECT IDENTIFIER ::= {id-CA-ECDH 3}
id-CA-ECDH-AES-CBC-CMAC-256 OBJECT IDENTIFIER ::= {id-CA-ECDH 4}
```

## 9.6 密钥协商算法

| 算法/格式 | DH | ECDH |
|-----------|-----|------|
| 密钥协商算法 | [PKCS#3] | ECKA [TR-03111] |
| X.509公钥格式 | [X9.42] | [TR-03111] |
| TLV公钥格式 | TLV，参见第9.4.3节 | TLV，参见第9.4.4节 |
| 临时公钥验证 | [RFC 2631] | [TR-03111] |

## 9.7 密钥派生机制

### 9.7.1 密钥派生函数

KDF(K,c)定义：
- **输入**：
  - 共享秘密值K（必要）
  - 32位高位优先的整数计数器c（必要）
- **输出**：八位组字节串密钥数据
- **动作**：keydata = H(K || c)

### 9.7.1.1 3DES密钥派生

- 使用SHA-1散列函数
- 派生128位密钥（不含奇偶校验位是112位）
- 使用keydata的1至8个八位组构成keydataA
- 使用keydata的9至16个八位组组成keydataB

### 9.7.1.2 AES密钥派生

- **128位密钥**：使用SHA-1，取keydata的1至16个八位组
- **192/256位密钥**：使用SHA-256
  - 192位：取keydata的1至24个八位组
  - 256位：取全部32个八位组

### 9.7.4 安全通讯密钥

利用共享密钥K派生：
- 加密密钥：KDFEnc(K) = KDF(K,1)
- 认证密钥：KDFMAC(K) = KDF(K,2)

## 重要说明

1. 电子机读旅行证件芯片可支持多个芯片认证密钥对（不同算法和/或密钥长度）
2. 多密钥情况下，必须在ChipAuthenticationInfo和ChipAuthenticationPublicKeyInfo中指定本地密钥标识符(keyId)
3. 芯片支持的芯片认证公钥在安全对象中提供
4. CA认证必须存储在DG14中，由被动认证保护其真实性