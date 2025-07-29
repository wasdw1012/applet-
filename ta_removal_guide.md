# TA (Terminal Authentication) 移除指南

## 需要删除的代码部分

### 1. 删除 CVCertificate 类（第 284-405 行）
这整个类都是用于 TA 的 CV 证书，可以完全删除。

### 2. 删除三个 TA 证书生成方法：
- `generate_cvca_certificate()` （第 797-850 行）
- `generate_dv_certificate()` （第 851-900 行）  
- `generate_is_certificate()` （第 902-951 行）

### 3. 修改 generate_eac_components 方法（第 780-795 行）

**原代码：**
```python
def generate_eac_components(self):
    """生成EAC组件"""
    print("\n 生成EAC组件")
    
    # 1. 生成CVCA证书链
    #  self.generate_cvca_certificate()
    #  self.generate_dv_certificate()
    #  self.generate_is_certificate()
    
    # 生成CA的EC密钥对
    self.generate_ca_ec_keys()
    
    # 生成DG14文件
    self.generate_dg14_file()
    
    print("✓ CA/DG14 生成完成")
```

**修改为：**
```python
def generate_eac_components(self):
    """生成EAC组件（仅CA，不含TA）"""
    print("\n 生成CA (Chip Authentication) 组件")
    
    # 生成CA的EC密钥对
    self.generate_ca_ec_keys()
    
    # 生成DG14文件
    self.generate_dg14_file()
    
    print("✓ CA/DG14 生成完成")
```

### 4. 清理 __init__ 方法中的 TA 相关属性
删除以下属性（如果有）：
- self.cvca_private_key
- self.cvca_cert_der
- self.dv_private_key
- self.dv_cert_der
- self.is_private_key
- self.is_cert_der

### 5. 更新注释和输出信息
- 第 1167 行的输出改为：`print(f" EAC组件: 已启用 (仅CA + DG14)")`

## 保留的代码（这些不要删除！）

### ✅ 必须保留：
1. **generate_ca_ec_keys()** 方法（第 953-1005 行）- CA 密钥生成
2. **generate_dg14_file()** 方法（第 1024-1077 行）- DG14 生成
3. **encode_length()** 方法（第 1007-1022 行）- DG14 需要用到
4. **extract_ec_p256_private_key()** 函数（第 211-232 行）- CA 密钥处理
5. **self.ca_ec_keys** 属性 - CA 密钥存储

## 验证步骤

删除后运行测试，确保：
1. CA 密钥正常生成（P-256）
2. DG14 文件正常生成
3. 其他功能（CSCA、DSC、AA）不受影响

## 为什么可以安全删除 TA？

1. **TA 和 CA 是独立的**：
   - TA 使用 CV 证书（Card Verifiable）
   - CA 使用 EC 密钥对
   - 两者没有依赖关系

2. **代码已经注释掉了 TA 调用**：
   - 第 785-787 行已经注释了 TA 证书生成
   - 说明 TA 本来就没有被使用

3. **CA 功能完整独立**：
   - CA 只需要 EC 密钥和 DG14
   - 不需要 CV 证书链