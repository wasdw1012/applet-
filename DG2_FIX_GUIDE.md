# DG2严格验证修复指南

## 问题诊断

您的DG2无法被严格端检测到头像的原因是缺少ISO/IEC 19794-5标准要求的完整数据结构。

### 当前实现的问题：

1. **缺少ISO/IEC 19794-5人脸记录格式**
   - 没有格式标识符 'FAC\x00'
   - 没有版本号 '010\x00'
   - 没有人脸信息块（性别、表情、姿态等）

2. **CBEFF头部不完整**
   - 缺少某些必需的标签
   - 标签值可能不符合标准

3. **数据结构层级错误**
   - 直接将JPEG数据放入生物数据块
   - 没有正确的人脸图像信息结构

## 严格DG2的正确结构

```
DG2 (Tag 0x75)
└── Biometric Information Group Template (Tag 0x7F61)
    ├── Number of instances (Tag 0x02): 0x01
    └── Biometric Information Template (Tag 0x7F60)
        ├── CBEFF Header (Tag 0xA1)
        │   ├── Patron Header Version (Tag 0x80): 0x01
        │   ├── BDB Format Owner (Tag 0x87): 0x0101
        │   ├── BDB Format Type (Tag 0x88): 0x0008
        │   ├── Biometric Type (Tag 0x81): 0x02 (facial)
        │   ├── Biometric Subtype (Tag 0x82): 0x00
        │   ├── Creation Date (Tag 0x85): 7 bytes
        │   ├── Validity Period (Tag 0x86): 8 bytes
        │   └── Creator (Tag 0x89): 18 bytes
        └── Biometric Data Block (Tag 0x5F2E)
            └── ISO/IEC 19794-5 Face Image Data
                ├── Facial Record Header (14 bytes)
                │   ├── Format Identifier: 'FAC\x00'
                │   ├── Version Number: '010\x00'
                │   ├── Record Length: 4 bytes
                │   └── Number of Faces: 2 bytes
                ├── Facial Information Block (20 bytes)
                │   ├── Record Length: 4 bytes
                │   ├── Feature Points: 2 bytes
                │   ├── Gender: 1 byte
                │   ├── Eye Color: 1 byte
                │   ├── Hair Color: 1 byte
                │   ├── Feature Mask: 3 bytes
                │   ├── Expression: 2 bytes (0x0001 = neutral)
                │   ├── Pose Angle: 3 bytes
                │   └── Pose Uncertainty: 3 bytes
                ├── Face Image Information (12 bytes)
                │   ├── Face Image Type: 1 byte (0x01 = full frontal)
                │   ├── Image Data Type: 1 byte (0x00 = JPEG)
                │   ├── Width: 2 bytes
                │   ├── Height: 2 bytes
                │   ├── Color Space: 1 byte
                │   ├── Source Type: 1 byte
                │   ├── Device Type: 2 bytes
                │   └── Quality: 2 bytes
                └── Face Image Data
                    └── JPEG data
```

## 使用修复版生成器

1. **使用提供的gen_dg2_fixed.py**：
   ```bash
   python gen_dg2_fixed.py passport_photo.jpg DG2.bin
   ```

2. **集成到您的系统**：
   ```python
   from gen_dg2_fixed import generate_strict_dg2
   
   # 在您的generate_dg2_file方法中
   def generate_dg2_file(self):
       print("  → 生成DG2文件...")
       
       # 使用严格的DG2生成器
       dg2_data = generate_strict_dg2(
           self.photo_path,
           os.path.join(self.output_dir, "DG2.bin")
       )
       
       # 计算哈希等其他操作...
   ```

## 关键参数说明

### 必须正确的值：
- **Expression**: 0x0001 (中性) 或 0x0000 (未指定)
- **Face Image Type**: 0x01 (全正面)
- **Pose Angle**: 接近 (0, 0, 0)
- **Quality**: >= 50
- **Image Size**: >= 240x320 像素

### CBEFF格式值：
- **Format Owner**: 0x0101 (ISO/IEC JTC1/SC37)
- **Format Type**: 0x0008 (人脸图像数据)
- **Biometric Type**: 0x02 (面部特征)

## 验证方法

1. **检查文件结构**：
   ```bash
   # 使用hex viewer查看前100字节
   xxd -l 100 DG2.bin
   
   # 应该看到:
   # - Tag 0x75 (DG2)
   # - Tag 0x7F61 (Biometric Info Group)
   # - 'FAC\x00' 标识符
   ```

2. **使用验证工具**：
   ```python
   # 验证DG2是否符合严格标准
   from icao_dg2_strict import validate_dg2_strict
   
   with open('DG2.bin', 'rb') as f:
       dg2_data = f.read()
   
   is_valid, errors = validate_dg2_strict(dg2_data)
   if not is_valid:
       print("验证失败:", errors)
   ```

## 常见错误和解决方案

1. **"No face image found"**
   - 原因：缺少ISO/IEC 19794-5格式头
   - 解决：使用完整的人脸数据格式

2. **"Invalid CBEFF structure"**
   - 原因：CBEFF头部标签缺失或错误
   - 解决：包含所有必需的CBEFF标签

3. **"Image quality too low"**
   - 原因：质量参数 < 50
   - 解决：设置质量值 >= 50

## 总结

严格的DG2验证要求完整实现ISO/IEC 19794-5标准。主要区别在于：
- 完整的数据结构（不能省略任何字段）
- 正确的嵌套层级
- 符合标准的参数值

使用提供的gen_dg2_fixed.py可以生成符合严格验证的DG2文件。