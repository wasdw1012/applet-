# CA (Chip Authentication) 安全报文切换实现分析

## 概述

该实现展示了电子护照中的 CA (Chip Authentication) 协议如何实现安全报文密钥的切换。CA 是在 BAC (Basic Access Control) 之后的额外认证步骤，用于：
1. 验证芯片的真实性
2. 建立新的会话密钥
3. 防止芯片克隆攻击

## 核心组件

### 1. MSE (Manage Security Environment) 指令处理

```java
// PassportApplet.java - processMSE 方法
private short processMSE(APDU apdu) {
    // 验证前置条件
    if (!hasEACKey() || !hasEACCertificate()) {
        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
    }
    if (!hasMutuallyAuthenticated() || hasTerminalAuthenticated()) {
        ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    
    // 解析 P1=0x41 (SET for computation), P2=0xA6 (KAT - Key Agreement Template)
    if (p1 == P1_SETFORCOMPUTATION && p2 == P2_KAT) {
        // 解析 Tag 0x91 - 公钥数据
        // 解析 Tag 0x84 - 密钥标识符（可选）
        
        // 执行芯片认证
        if (!crypto.authenticateChip(buffer, pubKeyOffset, pubKeyLen)) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
```

### 2. 芯片认证和密钥协商

```java
// PassportCrypto.java - authenticateChip 方法
public boolean authenticateChip(byte[] pubData, short offset, short length) {
    try {
        // 1. 验证并设置终端的公钥
        keyStore.ecPublicKey.setW(pubData, offset, length);
        if (!keyStore.ecPublicKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        // 2. 执行 ECDH 密钥协商
        keyAgreement.init(keyStore.ecPrivateKey);
        short secLength = keyAgreement.generateSecret(pubData, offset, 
                length, pubData, secOffset);

        // 3. 从共享密钥派生新的会话密钥
        // 派生 MAC 密钥
        deriveKey(pubData, secOffset, secLength, MAC_MODE, keysOffset);
        short macKeyOffset = keysOffset;
        keysOffset += PassportApplet.KEY_LENGTH;
        
        // 派生加密密钥
        deriveKey(pubData, secOffset, secLength, ENC_MODE, keysOffset);
        short encKeyOffset = keysOffset;
        
        // 4. 暂存新密钥到临时缓冲区
        Util.arrayCopyNonAtomic(pubData, macKeyOffset, keyStore.tmpKeys,
                (short) 0, PassportApplet.KEY_LENGTH);
        Util.arrayCopyNonAtomic(pubData, encKeyOffset, keyStore.tmpKeys,
                PassportApplet.KEY_LENGTH, PassportApplet.KEY_LENGTH);
        
        // 5. 标记需要在当前 APDU 处理完成后切换密钥
        eacChangeKeys[0] = true;
        return true;
    } catch (Exception e) {
        eacChangeKeys[0] = false;
        return false;
    }
}
```

### 3. 延迟密钥切换机制

```java
// PassportCrypto.java - updateCryptogramResponse 方法
private short updateCryptogramResponse(APDU apdu, short responseLength) {
    // ... 处理响应报文 ...
    
    // 在响应报文发送完成后执行密钥切换
    if (eacChangeKeys[0]) {
        eacChangeKeys[0] = false;
        
        // 从临时缓冲区设置新的安全报文密钥
        keyStore.setSecureMessagingKeys(keyStore.tmpKeys, (short) 0,
                keyStore.tmpKeys, (short) 16);
        
        // 清除临时密钥
        Util.arrayFillNonAtomic(keyStore.tmpKeys, (short) 0, (short) 32,
                (byte) 0x00);
        
        // 重置 SSC (Send Sequence Counter)
        Util.arrayFillNonAtomic(ssc, (short) 0, (short) ssc.length,
                (byte) 0x00);
    }
}
```

### 4. 密钥存储管理

```java
// KeyStore.java
public class KeyStore {
    // BAC/CA 后的安全报文密钥
    private DESKey sm_kMac, sm_kMac_a, sm_kMac_b;
    private DESKey sm_kEnc;
    
    // 临时密钥缓冲区（32字节：16字节 MAC + 16字节 ENC）
    byte[] tmpKeys;
    
    public void setSecureMessagingKeys(byte[] kMac, short kMac_offset, 
                                     byte[] kEnc, short kEnc_offset) {
        // 设置加密密钥
        sm_kEnc.setKey(kEnc, kEnc_offset);
        
        // 根据模式设置 MAC 密钥
        switch(mode) {
        case PassportCrypto.PERFECTWORLD_MODE:
            sm_kMac.setKey(kMac, kMac_offset);
            break;
        case PassportCrypto.CREF_MODE:
        case PassportCrypto.JCOP41_MODE:
            // 3DES MAC 需要两个密钥
            sm_kMac_a.setKey(kMac, kMac_offset);
            sm_kMac_b.setKey(kMac, (short)(kMac_offset + 8));
            break;
        }
    }
}
```

## 关键设计特点

### 1. 两阶段密钥切换
- **第一阶段**：在 `authenticateChip` 中计算新密钥并暂存
- **第二阶段**：在当前 APDU 响应完成后才真正切换密钥

### 2. 安全考虑
- 使用临时缓冲区存储新密钥，避免过早切换
- 确保当前 APDU 使用旧密钥完成安全报文处理
- 密钥切换后立即清零临时缓冲区
- 重置 SSC 计数器，防止重放攻击

### 3. 状态管理
```java
// 使用瞬态布尔数组标记密钥切换状态
boolean[] eacChangeKeys = JCSystem.makeTransientBooleanArray((short) 1, 
                          JCSystem.CLEAR_ON_RESET);
```

### 4. 密钥派生
- 从 ECDH 共享密钥派生会话密钥
- 分别派生 MAC 密钥和加密密钥
- 支持不同的加密模式（PERFECTWORLD、CREF、JCOP41）

## 实现流程

1. **终端发送 MSE 指令**
   - INS = 0x22, P1 = 0x41, P2 = 0xA6
   - 数据包含终端的 EC 公钥

2. **芯片执行 CA**
   - 验证终端公钥有效性
   - 执行 ECDH 密钥协商
   - 派生新的会话密钥
   - 暂存新密钥，设置切换标志

3. **响应处理**
   - 使用旧密钥保护响应报文
   - 发送响应后切换到新密钥
   - 清理临时数据

4. **后续通信**
   - 使用新的会话密钥进行安全报文
   - SSC 从 0 重新开始计数

## 安全优势

1. **前向安全性**：即使旧密钥泄露，新会话密钥仍然安全
2. **防克隆**：只有真实芯片拥有私钥，能完成密钥协商
3. **密钥新鲜性**：每次 CA 都生成新的会话密钥
4. **原子性操作**：密钥切换在 APDU 边界进行，避免中间状态

这种实现方式确保了 CA 协议的安全性和可靠性，是电子护照安全机制的重要组成部分。