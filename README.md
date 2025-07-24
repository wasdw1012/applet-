# CA (Chip Authentication) 认证机制核心代码分析

本仓库收集了NFCPassportReader中CA认证机制的核心实现代码，用于精准反推和佐证卡端applet的部署。

## 目录结构

- `src/CA_Core/` - CA认证的核心实现逻辑
- `src/DataGroups/` - 数据组相关代码（DG14等）
- `src/Utils/` - 工具函数（密钥处理、加密等）
- `src/Security/` - 安全相关的信息结构
- `src/APDU_Commands/` - APDU命令实现

## CA认证流程概述

1. **读取DG14** - 包含芯片认证公钥信息
2. **解析安全信息** - 提取ChipAuthenticationInfo和ChipAuthenticationPublicKeyInfo
3. **生成临时密钥对** - 基于DG14中的公钥参数
4. **发送公钥到护照** - 通过MSE Set KAT或MSE Set AT命令
5. **计算共享密钥** - 使用ECDH或DH算法
6. **重启安全消息** - 使用新的会话密钥

## 关键组件

### OID定义
- DH相关：`0.4.0.127.0.7.2.2.1.1` (ID_PK_DH_OID)
- ECDH相关：`0.4.0.127.0.7.2.2.1.2` (ID_PK_ECDH_OID)
- 各种加密算法组合的OID

### 密钥算法
- DH/ECDH密钥协商
- 3DES-CBC-CBC
- AES-CBC-CMAC (128/192/256位)

### 标签定义
- 0x80 - OID
- 0x84 - Key ID
- 0x91 - 密钥数据（DH/ECDH公钥）
- 0x7C - General Authenticate包装

## 重要说明

这些代码用于理解CA认证的验证端逻辑，以便精准实现卡端applet的对应功能。