# CA认证：ICAO 9303标准与NFCPassportReader实现对比

## 概述

本文档对比分析ICAO 9303第11部分的CA认证标准规范与NFCPassportReader（Andy的实现）之间的关系。

## 核心概念对比

### 1. 协议流程

**ICAO 9303规范**：
1. 芯片向终端发送静态DH公钥(PKIC)和域参数(DIC)
2. 终端生成临时DH密钥对并发送公钥(PKDH,IFD)
3. 双方计算共享密钥K并派生会话密钥

**NFCPassportReader实现**：
```swift
// 1. 从DG14获取芯片公钥（在初始化时完成）
// 2. 生成临时密钥对
var ephemeralKeyPair : OpaquePointer? = nil
let pctx = EVP_PKEY_CTX_new(publicKey, nil)
EVP_PKEY_keygen_init(pctx)
EVP_PKEY_keygen(pctx, &ephemeralKeyPair)

// 3. 计算共享密钥
let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair:ephemeralKeyPair!, publicKey:publicKey)
```

### 2. APDU命令实现

#### MSE:Set KAT（3DES情况）

**ICAO规范**：
- CLA: 上下文特定
- INS: 0x22
- P1/P2: 0x41A6
- Data: Tag 0x91（公钥） + Tag 0x84（密钥ID，可选）

**NFCPassportReader实现**：
```swift
if cipherAlg.hasPrefix("DESede") {
    var idData : [UInt8] = []
    if let keyId = keyId {
        idData = intToBytes(val:keyId, removePadding:true)
        idData = wrapDO(b:0x84, arr:idData)  // Tag 0x84
    }
    let wrappedKeyData = wrapDO(b:0x91, arr:keyData)  // Tag 0x91
    _ = try await self.tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData))
}
```

#### MSE:Set AT + GENERAL AUTHENTICATE（AES情况）

**ICAO规范**：
1. MSE:Set AT: P1/P2=0x41A4, Data: Tag 0x80（OID）+ Tag 0x84（密钥ID）
2. GENERAL AUTHENTICATE: INS=0x86, Data: Tag 0x7C包含Tag 0x80（公钥）

**NFCPassportReader实现**：
```swift
if cipherAlg.hasPrefix("AES") {
    // 1. MSE:Set AT
    _ = try await self.tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)
    
    // 2. GENERAL AUTHENTICATE
    let data = wrapDO(b: 0x80, arr:keyData)
    gaSegments = self.chunk(data: data, segmentSize: COMMAND_CHAINING_CHUNK_SIZE)
    try await self.handleGeneralAuthentication()
}
```

### 3. 数据结构对比

#### ChipAuthenticationInfo

**ICAO ASN.1定义**：
```asn1
ChipAuthenticationInfo ::= SEQUENCE {
    protocol OBJECT IDENTIFIER(...),
    version INTEGER,
    keyId INTEGER OPTIONAL
}
```

**NFCPassportReader实现**：
```swift
public class ChipAuthenticationInfo : SecurityInfo {
    var oid : String        // 对应protocol
    var version : Int       // 对应version
    var keyId : Int?        // 对应keyId OPTIONAL
}
```

### 4. OID定义对比

**ICAO定义的OID结构**：
- `bsi-de protocols(2) smartcard(2) 3` → `0.4.0.127.0.7.2.2.3`

**实际OID值完全一致**：
- id-CA-DH-3DES-CBC-CBC: `0.4.0.127.0.7.2.2.3.1.1`
- id-CA-ECDH-AES-CBC-CMAC-128: `0.4.0.127.0.7.2.2.3.2.2`
- 等等...

### 5. 密钥派生对比

**ICAO规范**：
- KDF(K,c) = H(K || c)
- 加密密钥：KDFEnc(K) = KDF(K,1)
- MAC密钥：KDFMAC(K) = KDF(K,2)

**NFCPassportReader实现**：
```swift
// 完全遵循ICAO规范
let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, mode: .ENC_MODE)  // mode=1
let ksMac = try smskg.deriveKey(keySeed: sharedSecret, mode: .MAC_MODE)  // mode=2

// 内部实现
let modeArr : [UInt8] = [0x00, 0x00, 0x00, mode.rawValue]
let hashResult = try getHash(algo: digestAlgo, dataElements: [keySeed, modeArr])
```

## 实现特点

### 1. 错误处理增强

NFCPassportReader增加了对缺少ChipAuthenticationInfo的处理：
```swift
// 法国护照可能缺少ChipAuthInfo，从公钥类型推断
if let oid = inferOID(fromPublicKeyOID:chipAuthPublicKeyInfo.oid) {
    chipAuthInfoOID = oid
}
```

### 2. 命令链支持

对于AES的GENERAL AUTHENTICATE，实现了命令链分段：
```swift
gaSegments = self.chunk(data: data, segmentSize: 224)
```

### 3. 多密钥支持

完整实现了多密钥支持逻辑：
- 遍历所有公钥尝试认证
- 使用keyId区分不同密钥

## 结论

NFCPassportReader的CA认证实现：
1. **严格遵循**ICAO 9303标准的协议流程
2. **完整实现**了所有必需的APDU命令
3. **正确使用**了标准定义的OID和数据结构
4. **增强处理**了一些边缘情况（如法国护照）
5. **底层逻辑**与ICAO标准完全一致

这为卡端applet的CA功能实现提供了可靠的参考标准。