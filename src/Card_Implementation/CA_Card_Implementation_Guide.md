# 卡端CA认证实现指南

基于ICAO 9303标准和NFCPassportReader的验证端实现，本文档提供卡端applet实现CA认证的指导。

## 卡端需要实现的核心功能

### 1. 密钥存储

```java
// 卡端需要存储的密钥
private KeyPair caKeyPair;      // CA静态密钥对
private byte keyId;             // 密钥标识符（多密钥时使用）
```

### 2. DG14数据结构

卡端需要在DG14中存储以下ASN.1结构：

```asn1
-- SecurityInfos (存储在DG14中)
SecurityInfos ::= SET OF SecurityInfo

-- 包含两种SecurityInfo
ChipAuthenticationInfo ::= SEQUENCE {
    protocol OBJECT IDENTIFIER,  -- 如：id-CA-ECDH-AES-CBC-CMAC-128
    version INTEGER,            -- 必须为1
    keyId INTEGER OPTIONAL      -- 多密钥时需要
}

ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
    protocol OBJECT IDENTIFIER,  -- id-PK-DH 或 id-PK-ECDH
    chipAuthenticationPublicKey SubjectPublicKeyInfo,
    keyId INTEGER OPTIONAL
}
```

### 3. APDU命令处理

#### 3.1 MSE:Set KAT (3DES模式)

```java
// 处理 CLA=00/0C INS=22 P1=41 P2=A6
private void handleMSESetKAT(APDU apdu) {
    byte[] data = apdu.getDataIn();
    
    // 解析TLV数据
    // Tag 0x91: 终端的临时公钥
    byte[] terminalPublicKey = parseTLV(data, 0x91);
    
    // Tag 0x84: 密钥ID（可选）
    byte selectedKeyId = parseTLV(data, 0x84);
    
    // 执行密钥协商
    byte[] sharedSecret = performKeyAgreement(terminalPublicKey, selectedKeyId);
    
    // 派生新的会话密钥
    deriveSessionKeys(sharedSecret);
    
    // 返回9000
    ISOException.throwIt(ISO7816.SW_NO_ERROR);
}
```

#### 3.2 MSE:Set AT + GENERAL AUTHENTICATE (AES模式)

```java
// Step 1: MSE:Set AT
// CLA=00/0C INS=22 P1=41 P2=A4
private void handleMSESetAT(APDU apdu) {
    byte[] data = apdu.getDataIn();
    
    // Tag 0x80: 算法OID（去掉0x06标签）
    byte[] oid = parseTLV(data, 0x80);
    
    // Tag 0x84: 密钥ID（可选）
    byte keyId = parseTLV(data, 0x84);
    
    // 选择并初始化CA协议
    selectCAProtocol(oid, keyId);
}

// Step 2: GENERAL AUTHENTICATE
// CLA=00/10 INS=86 P1=00 P2=00
private void handleGeneralAuthenticate(APDU apdu) {
    byte[] data = apdu.getDataIn();
    
    // Tag 0x7C: 动态认证数据
    byte[] dynAuthData = parseTLV(data, 0x7C);
    
    // Tag 0x80: 终端公钥（在0x7C内）
    byte[] terminalPublicKey = parseTLV(dynAuthData, 0x80);
    
    // 执行密钥协商
    byte[] sharedSecret = performKeyAgreement(terminalPublicKey);
    
    // 派生新会话密钥
    deriveSessionKeys(sharedSecret);
    
    // 响应0x7C标签（CA v1中通常为空）
    apdu.setOutgoing();
    apdu.setOutgoingLength((short)2);
    byte[] response = {0x7C, 0x00};
    apdu.sendBytesLong(response, 0, 2);
}
```

### 4. 密钥协商实现

```java
private byte[] performKeyAgreement(byte[] terminalPublicKey, byte keyId) {
    // 1. 验证终端公钥
    if (!validatePublicKey(terminalPublicKey)) {
        ISOException.throwIt(SW_WRONG_DATA);
    }
    
    // 2. 选择正确的CA私钥
    PrivateKey caPrivateKey = selectCAPrivateKey(keyId);
    
    // 3. 执行DH/ECDH密钥协商
    KeyAgreement ka = KeyAgreement.getInstance(
        isECDH ? "ECDH" : "DH"
    );
    ka.init(caPrivateKey);
    ka.doPhase(terminalPublicKey, true);
    
    // 4. 生成共享密钥
    byte[] sharedSecret = ka.generateSecret();
    
    return sharedSecret;
}
```

### 5. 会话密钥派生

```java
private void deriveSessionKeys(byte[] sharedSecret) {
    // 按照ICAO标准派生密钥
    // KDF(K,c) = H(K || c)
    
    // 派生加密密钥：c = 1
    byte[] ksEnc = KDF(sharedSecret, 0x00000001);
    
    // 派生MAC密钥：c = 2
    byte[] ksMac = KDF(sharedSecret, 0x00000002);
    
    // 重置SSC为0
    ssc = new byte[blockSize]; // 64位(3DES)或128位(AES)
    
    // 更新安全消息会话
    updateSecureMessaging(ksEnc, ksMac, ssc);
}

private byte[] KDF(byte[] K, int c) {
    MessageDigest md;
    if (keyLength <= 128) {
        md = MessageDigest.getInstance("SHA-1");
    } else {
        md = MessageDigest.getInstance("SHA-256");
    }
    
    md.update(K);
    md.update(intToBytes(c)); // 32位大端序
    
    byte[] hash = md.digest();
    
    // 根据需要截取
    return extractKeyBytes(hash, keyLength);
}
```

### 6. 支持的算法组合

卡端应根据需求支持以下一种或多种组合：

| OID | 密钥协商 | 对称加密 | 密钥长度 |
|-----|---------|---------|---------|
| 0.4.0.127.0.7.2.2.3.1.1 | DH | 3DES | 112 |
| 0.4.0.127.0.7.2.2.3.1.2 | DH | AES | 128 |
| 0.4.0.127.0.7.2.2.3.2.1 | ECDH | 3DES | 112 |
| 0.4.0.127.0.7.2.2.3.2.2 | ECDH | AES | 128 |
| 0.4.0.127.0.7.2.2.3.2.3 | ECDH | AES | 192 |
| 0.4.0.127.0.7.2.2.3.2.4 | ECDH | AES | 256 |

### 7. 安全考虑

1. **私钥保护**：CA私钥必须存储在安全存储区
2. **公钥验证**：必须验证接收到的终端公钥有效性
3. **防重放**：每次CA认证使用新的共享密钥
4. **错误处理**：不要泄露敏感信息

### 8. 测试要点

1. 验证DG14正确包含CA信息
2. 测试3DES和AES两种模式
3. 验证密钥派生的正确性
4. 确认新会话密钥生效
5. 测试多密钥场景（如果支持）

## 实现流程总结

```
1. 初始化阶段
   - 生成CA密钥对
   - 构建DG14数据
   - 存储私钥

2. 运行时处理
   - 接收MSE命令选择协议
   - 接收终端公钥
   - 执行密钥协商
   - 派生会话密钥
   - 切换到新的安全通道

3. 后续通信
   - 使用新的会话密钥
   - SSC从0开始计数
```