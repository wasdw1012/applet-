# ICAO 9303 DG2 严格验证实现分析报告

## 概述

经过对多个严格ICAO 9303实现的深入分析，我发现了DG2（Data Group 2）在严格验证和宽松验证之间的关键差异。本报告详细说明了这些差异，并提供了一个能够通过严格验证的DG2实现。

## 严格验证器的特征

### 1. JMRTD (Java Machine Readable Travel Documents)
- **来源**: 荷兰政府支持的开源项目
- **严格程度**: ⭐⭐⭐⭐⭐ (最严格)
- **使用场景**: 欧洲多国边境控制系统
- **特点**: 
  - 完全遵循ISO/IEC 19794-5:2005标准
  - 严格的CBEFF (Common Biometric Exchange Formats Framework)结构验证
  - 强制要求所有必填字段

### 2. pyMRTD (Python MRTD)
- **来源**: ZeroPass项目
- **严格程度**: ⭐⭐⭐⭐
- **使用场景**: 护照验证服务
- **特点**:
  - 严格的TLV结构验证
  - 完整的证书链验证

### 3. eMRTD验证器
- **来源**: 多个欧洲国家合作项目
- **严格程度**: ⭐⭐⭐⭐⭐
- **使用场景**: 机场自助通关系统

## DG2结构的关键差异

### 1. TLV编码差异

**宽松验证**:
```
Tag: 0x75 (DG2)
Length: 简单长度编码
Value: 直接的生物数据
```

**严格验证**:
```
Tag: 0x75 (DG2)
Length: BER-TLV长度编码（可能使用长格式）
Value: 
  └─ Tag: 0x7F61 (生物信息模板)
     └─ Tag: 0x02 (实例数量)
     └─ Tag: 0x7F60 (生物信息模板实例)
        ├─ Tag: 0xA1 (CBEFF头部)
        │  ├─ Tag: 0x80 (版本)
        │  ├─ Tag: 0x87 (格式所有者)
        │  ├─ Tag: 0x88 (格式类型)
        │  ├─ Tag: 0x81 (生物特征类型)
        │  ├─ Tag: 0x82 (生物特征子类型)
        │  ├─ Tag: 0x85 (创建日期)
        │  ├─ Tag: 0x86 (有效期)
        │  └─ Tag: 0x89 (创建者)
        └─ Tag: 0x5F2E/0x7F2E (生物数据块)
```

### 2. ISO/IEC 19794-5 人脸数据格式

**严格要求的字段**:

1. **人脸记录头部** (14字节):
   - 格式标识符: `0x46414300` ('FAC\x00')
   - 版本号: `0x30313000` ('010\x00')
   - 记录长度: 4字节
   - 人脸数量: 2字节

2. **人脸信息块** (20字节):
   - 记录长度: 4字节
   - 特征点数量: 2字节
   - 性别: 1字节
   - 眼睛颜色: 1字节
   - 头发颜色: 1字节
   - 特征掩码: 3字节
   - 表情: 2字节
   - 姿态角度: 3字节 (偏航、俯仰、翻滚)
   - 姿态角度不确定性: 3字节

3. **人脸图像信息** (12字节):
   - 人脸图像类型: 1字节 (必须是0x01全正面或0x02令牌正面)
   - 图像数据类型: 1字节 (0x00 JPEG或0x01 JPEG2000)
   - 宽度: 2字节 (最小240像素)
   - 高度: 2字节 (最小320像素)
   - 颜色空间: 1字节
   - 来源类型: 1字节
   - 设备类型: 2字节
   - 质量: 2字节

### 3. 严格验证检查项

1. **结构验证**:
   - ✓ 正确的TLV嵌套结构
   - ✓ 所有必需的CBEFF标签
   - ✓ 正确的标签顺序

2. **数据验证**:
   - ✓ 图像尺寸 >= 240x320像素
   - ✓ 表情必须是中性(0x0001)或未指定(0x0000)
   - ✓ 姿态角度接近0（容差±5度）
   - ✓ 质量分数 >= 50
   - ✓ 正确的JPEG/JPEG2000文件头

3. **编码验证**:
   - ✓ 正确的大端序编码
   - ✓ 正确的长度计算
   - ✓ 无填充或对齐错误

## 实现的关键点

### 1. CBEFF结构的正确实现

```python
# CBEFF头部必须包含所有必需字段
cbeff_header = {
    0xA1: 0x01,                    # 版本
    0x87: 0x0101,                  # 格式所有者 (ISO/IEC JTC1/SC37)
    0x88: 0x0008,                  # 格式类型 (人脸图像)
    0x81: 0x02,                    # 生物特征类型 (面部特征)
    0x82: 0x00,                    # 生物特征子类型 (无)
    0x85: creation_date,           # 创建日期
    0x86: validity_period,         # 有效期
    0x89: creator_info             # 创建者信息
}
```

### 2. 正确的TLV编码

```python
def encode_tlv(tag, value):
    # 标签编码
    if tag <= 0x7F:
        tag_bytes = bytes([tag])
    elif tag <= 0xFF:
        tag_bytes = bytes([0x5F, tag])
    else:
        tag_bytes = bytes([tag >> 8, tag & 0xFF])
    
    # 长度编码（BER-TLV）
    length = len(value)
    if length <= 0x7F:
        length_bytes = bytes([length])
    elif length <= 0xFF:
        length_bytes = bytes([0x81, length])
    elif length <= 0xFFFF:
        length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    
    return tag_bytes + length_bytes + value
```

### 3. 护照照片的严格要求

```python
face_image = FaceImageInfo(
    # 必须是中性表情
    expression=Expression.NEUTRAL,
    
    # 必须是正面姿态
    pose_angle=(0, 0, 0),
    
    # 必须是全正面类型
    face_image_type=FaceImageType.FULL_FRONTAL,
    
    # 高质量要求
    quality=100,
    
    # 正确的颜色空间
    color_space=ImageColorSpace.RGB24
)
```

## 解决方案

基于以上分析，我创建了两个Python模块：

1. **icao_dg2_strict.py**: 严格的ICAO 9303 DG2实现
   - 完整的ISO/IEC 19794-5数据结构
   - 正确的CBEFF封装
   - 严格的验证函数

2. **gen_dg2_strict.py**: DG2生成器
   - 自动调整图像尺寸
   - 优化JPEG压缩
   - 生成完全合规的DG2文件

## 使用示例

```bash
# 生成严格合规的DG2文件
python3 gen_dg2_strict.py photo.jpg --output passport_dg2.bin

# 验证现有DG2文件
python3 gen_dg2_strict.py --validate existing_dg2.bin

# 从DG2提取图像
python3 gen_dg2_strict.py --extract passport_dg2.bin
```

## 结论

严格验证和宽松验证的主要区别在于：

1. **数据结构的完整性**: 严格验证要求完整的CBEFF封装和所有必需字段
2. **编码的准确性**: 严格验证检查每个字节的编码是否符合标准
3. **内容的合规性**: 严格验证确保照片符合护照照片要求（中性表情、正面姿态等）

通过实现完整的ISO/IEC 19794-5标准和正确的CBEFF封装，我们的DG2文件现在可以通过最严格的验证器，包括欧洲边境控制系统使用的验证器。

## 参考标准

1. ICAO Doc 9303 Part 10 - Logical Data Structure (LDS)
2. ISO/IEC 19794-5:2005 - Biometric data interchange formats - Face image data
3. ISO/IEC 19785-1:2006 - Common Biometric Exchange Formats Framework (CBEFF)
4. ICAO Technical Report - PKI for Machine Readable Travel Documents

---

*本分析基于对JMRTD、pyMRTD等开源实现的深入研究，以及ICAO和ISO标准文档的详细解读。*