# DG2 完整结构实现总结

## PyMRTD 兼容的 DG2 结构

经过分析，PyMRTD 期望的完整 DG2 结构如下：

```
75 (DG2 - Data Group 2)
└── [长度]
    └── 7F61 (生物特征信息组模板 - Biometric Info Group Template)
        └── [长度]
            ├── 02 (生物特征实例数量 - Number of Instances)
            │   └── [长度]
            │       └── 01 (数量值：1个实例)
            └── 7F60 (生物特征信息模板 - Biometric Info Template) ← 这是缺失的层！
                └── [长度]
                    ├── A1 (生物特征头模板 - Biometric Header Template)
                    │   └── [长度]
                    │       ├── 80 (ICAO头版本)
                    │       ├── 81 (生物特征类型)
                    │       ├── 82 (生物特征子类型)
                    │       ├── 83 (创建日期时间)
                    │       ├── 85 (有效期)
                    │       ├── 86 (创建者)
                    │       ├── 87 (格式所有者)
                    │       └── 88 (格式类型)
                    └── 5F2E (生物特征数据块 - Biometric Data Block)
                        └── [长度]
                            └── [JPEG2000图像数据]
```

## 关键发现

1. **缺失的 7F60 层**：PyMRTD 期望在 7F61 内部有一个 7F60（生物特征信息模板）包装层
2. **错误信息解释**：
   - "期望 7F60 实际：A1" 表示 PyMRTD 在解析 7F61 内容时，期望先看到 7F60，但实际直接遇到了 A1

## 实现更改

### 之前的结构（不兼容）
```
75 → 7F61 → (02 + A1 + 5F2E)
```

### 更新后的结构（PyMRTD 兼容）
```
75 → 7F61 → (02 + 7F60 → (A1 + 5F2E))
```

## 代码更改要点

1. **添加了 BIOMETRIC_INFO_TEMPLATE_TAG = 0x7F60**
2. **修改了组装逻辑**：
   ```python
   # 构建生物特征信息模板 (7F60)
   biometric_info_content = biometric_header + biometric_data
   biometric_info_template = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, biometric_info_content)
   
   # 构建生物特征信息组模板 (7F61)
   biometric_info_group_content = sample_number + biometric_info_template
   ```

3. **更新了验证函数**：支持解析带有 7F60 层的新结构，同时保持向后兼容

## 标准参考

根据 ICAO 9303 Part 10 标准：
- 7F61 是生物特征信息组模板（可包含多个生物特征实例）
- 7F60 是单个生物特征信息模板（包含一个实例的头和数据）
- 当有多个生物特征实例时，每个实例都应该用 7F60 包装

## 测试建议

1. 使用更新后的代码生成 DG2 文件
2. 用 PyMRTD 验证新生成的文件
3. 如果仍有问题，检查生成的二进制数据的十六进制转储

---
更新时间：2024-12-29
说明：这是为了兼容 PyMRTD 的严格验证要求而进行的结构调整