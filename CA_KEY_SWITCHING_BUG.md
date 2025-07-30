# CA (Chip Authentication) 密钥切换时序问题

## 问题概述

CAP 分支中的 CA 实现存在严重的密钥切换时序错误。密钥在 MSE 响应发送前就被切换，导致响应使用了错误的密钥进行安全报文保护。

## 问题详情

### 当前错误实现（CAP 分支）

1. **MSE 处理流程**（PassportApplet.java）：
   ```java
   // 第607行：派生新密钥并立即切换
   deriveSessionKeysFromCA(sharedSecret, (short)0, secretLen);
   ```

2. **密钥切换位置**（PassportApplet.java 第701行）：
   ```java
   // 在 deriveSessionKeysFromCA 方法中立即切换密钥
   keyStore.setSecureMessagingKeys(tempKeyMaterial, (short)16, tempKeyMaterial, (short)0);
   ```

3. **响应包装**（PassportApplet.java 第310行）：
   ```java
   // 使用已经切换的新密钥进行 SM 包装
   responseLength = crypto.wrapResponseAPDU(ssc, apdu, crypto
           .getApduBufferOffset(responseLength), responseLength, sw1sw2);
   ```

### 正确实现（JMRTD 分支）

1. **延迟切换机制**：
   - 使用 `eacChangeKeys[0]` 标志
   - 新密钥暂存在 `tmpKeys` 缓冲区
   - 在 `wrapResponseAPDU` **完成后**才切换

2. **正确的时序**：
   ```java
   // PassportCrypto.java
   // 1. CA 过程中只设置标志
   eacChangeKeys[0] = true;
   
   // 2. 在 wrapResponseAPDU 方法的末尾
   if (eacChangeKeys[0]) {
       eacChangeKeys[0] = false;
       keyStore.setSecureMessagingKeys(keyStore.tmpKeys, (short) 0,
               keyStore.tmpKeys, (short) 16);
   }
   ```

## 影响

1. **协议违规**：违反 ICAO Doc 9303 标准要求
2. **通信失败**：终端无法验证 MSE 响应的 MAC
3. **CA 失败**：整个芯片认证流程无法完成

## 根本原因

CAP 分支采用了"一步式"CA 实现，试图简化流程，但忽略了关键的密钥切换时序要求：
- MSE 响应必须使用 BAC 建立的旧密钥
- 只有在响应成功发送后才能切换到 CA 派生的新密钥

## 修复方案

需要实现延迟密钥切换机制：

1. **添加延迟切换标志**：
   ```java
   private boolean[] caKeysPending;  // 瞬态布尔数组
   ```

2. **修改密钥派生**：
   - 不立即调用 `setSecureMessagingKeys`
   - 将新密钥暂存到临时缓冲区
   - 设置 `caKeysPending[0] = true`

3. **修改 PassportCrypto.wrapResponseAPDU**：
   - 在方法末尾检查 `caKeysPending[0]`
   - 如果为 true，执行密钥切换
   - 清除标志和临时缓冲区

## 测试建议

1. 使用协议分析器捕获 MSE 交互
2. 验证 MSE 响应的 MAC 使用的是 BAC 密钥
3. 验证后续命令使用新的 CA 密钥

## 优先级

**高** - 这是阻塞性问题，会导致 CA 完全无法工作

## 相关文件

- PassportApplet.java（第607行、第701行）
- KeyStore.java（setSecureMessagingKeys 方法）
- PassportCrypto.java（需要添加延迟切换逻辑）

---
记录时间：2024-12-29
记录人：CA 实现分析