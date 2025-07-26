# ICAO 9303 DG2 严格验证实现

## 问题描述

您的DG2文件在宽松验证下可以读取头像，但在严格验证下无法读取。这是因为严格验证器（如欧洲边境控制系统）要求完全符合ICAO 9303和ISO/IEC 19794-5标准。

## 解决方案

我分析了多个严格验证器的实现（JMRTD、pyMRTD等），发现了关键差异并创建了完全合规的实现。

### 主要文件

1. **icao_dg2_strict.py** - 严格的DG2实现库
   - 完整的ISO/IEC 19794-5数据结构
   - 正确的CBEFF封装
   - 严格的验证函数

2. **gen_dg2_strict.py** - DG2生成器工具
   - 从照片生成合规的DG2文件
   - 验证现有DG2文件
   - 提取DG2中的图像

3. **DG2_STRICT_ANALYSIS.md** - 详细的技术分析报告

## 快速使用

### 安装依赖
```bash
pip install pillow
```

### 生成严格合规的DG2
```bash
python3 gen_dg2_strict.py your_photo.jpg --output passport_dg2.bin
```

### 验证DG2文件
```bash
python3 gen_dg2_strict.py --validate your_dg2.bin
```

### 提取DG2中的图像
```bash
python3 gen_dg2_strict.py --extract your_dg2.bin
```

## 关键差异总结

### 1. 数据结构
- **宽松**: 简单的TLV结构
- **严格**: 完整的CBEFF封装 + 嵌套TLV结构

### 2. 必需字段
- **宽松**: 只需要基本图像数据
- **严格**: 需要所有ISO/IEC 19794-5定义的字段

### 3. 验证规则
- **宽松**: 基本格式检查
- **严格**: 
  - 图像尺寸 >= 240x320
  - 中性表情
  - 正面姿态
  - 高质量分数
  - 正确的编码

## 技术规格

生成的DG2文件符合：
- ICAO Doc 9303 Part 10
- ISO/IEC 19794-5:2005 (人脸图像数据)
- ISO/IEC 19785-1:2006 (CBEFF)

## 测试结果

我们的实现已通过以下验证器测试：
- ✅ JMRTD (最严格的Java实现)
- ✅ pyMRTD验证器
- ✅ 标准ICAO合规性检查

## 联系

如有问题，请参考详细的技术分析文档 `DG2_STRICT_ANALYSIS.md`。