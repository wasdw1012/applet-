# DG2 数据分析工具

符合 ICAO 9303 标准的 DG2 (Data Group 2) 文件生成与分析工具集。

## 概述

DG2 是电子护照和其他机读旅行证件中用于存储面部生物特征数据的数据组。本工具集提供了完整的 DG2 文件生成、解析、分析和可视化功能。

## 工具集组成

### 1. `gen_dg2_simple.py` - DG2 文件生成器
生成符合 ICAO 9303 标准的 DG2 文件。

**功能特点：**
- 将普通图像转换为 DG2 格式
- 自动调整图像尺寸至标准护照照片大小
- 生成面部特征点（近似位置）
- 添加完整的生物特征元数据

**使用方法：**
```bash
python3 gen_dg2_simple.py <图像文件> [选项]

选项：
  --size {compact,normal,quality}  尺寸模式 (默认: compact)
  --out <文件名>                   输出文件名 (默认: DG2.bin)

示例：
  python3 gen_dg2_simple.py photo.jpg
  python3 gen_dg2_simple.py photo.jpg --size normal --out passport_dg2.bin
```

### 2. `dg2_analysis.py` - DG2 数据分析器
全面分析 DG2 文件的结构和内容。

**主要功能：**

#### 分析 (analyze)
解析并显示 DG2 文件的基本信息。
```bash
python3 dg2_analysis.py analyze <DG2文件>
python3 dg2_analysis.py analyze <DG2文件> --json  # JSON格式输出
```

#### 提取图像 (extract)
从 DG2 文件中提取面部图像。
```bash
python3 dg2_analysis.py extract <DG2文件> --output <输出图像>
```

#### 可视化 (visualize)
生成 DG2 数据的可视化图表。
```bash
# 可视化文件结构
python3 dg2_analysis.py visualize <DG2文件> --structure --output structure.png

# 可视化特征点
python3 dg2_analysis.py visualize <DG2文件> --features --output features.png
```

#### 生成报告 (report)
生成详细的分析报告。
```bash
python3 dg2_analysis.py report <DG2文件> --output report.txt
```

### 3. `dg2_demo.py` - 演示脚本
展示所有 DG2 分析功能的交互式演示。
```bash
python3 dg2_demo.py
```

## DG2 文件结构

DG2 文件采用 BER-TLV (Basic Encoding Rules - Tag Length Value) 编码，包含以下主要组件：

```
DG2 (Tag: 0x75)
└── Biometric Information Group Template (Tag: 0x7F61)
    ├── Sample Number (Tag: 0x02)
    └── Biometric Information Template (Tag: 0x7F60)
        ├── Biometric Header Template (Tag: 0xA1)
        │   ├── ICAO Header Version (Tag: 0x80)
        │   ├── Biometric Type (Tag: 0x81)
        │   ├── Biometric Subtype (Tag: 0x82)
        │   ├── Creation Date/Time (Tag: 0x83)
        │   ├── Validity Period (Tag: 0x85)
        │   ├── Creator (Tag: 0x86)
        │   ├── Format Owner (Tag: 0x87)
        │   ├── Format Type (Tag: 0x88)
        │   ├── Image Width (Tag: 0x90)
        │   ├── Image Height (Tag: 0x91)
        │   └── Feature Points (Tag: 0x92)
        └── Biometric Data Block (Tag: 0x5F2E)
            └── [JPEG/JPEG2000 图像数据]
```

## 分析输出示例

### 基本分析
```
[分析结果]
文件大小: 5178 字节
SHA256: 7b870c891dec109fd122e82b881e0da2e7782213faa99b58ee0181360e696966
图像格式: JPEG
图像尺寸: 300x400
特征点数: 4
```

### JSON 格式输出
```json
{
  "file_info": {
    "path": "sample_dg2.bin",
    "size": 5178,
    "sha256": "7b870c891dec109fd122e82b881e0da2e7782213faa99b58ee0181360e696966"
  },
  "structure": {
    "dg2_tag": 117,
    "dg2_length": 5174,
    "sample_number": 1,
    "image_data_length": 5045
  },
  "metadata": {
    "header_version": "1.1",
    "biometric_type": 2,
    "biometric_type_name": "Facial Features",
    "creation_datetime": "20250731051506Z",
    "validity_period": "20250731 - 20350729",
    "format_type_name": "JPEG",
    "image_width": 300,
    "image_height": 400,
    "feature_points_count": 4
  }
}
```

## 特征点格式

每个特征点包含以下信息：
- **Type**: 特征类型（1 = 面部特征）
- **Major**: 主要特征代码（1=左眼, 2=右眼, 3=鼻尖, 4=嘴巴中心）
- **Minor**: 次要特征代码（通常为 0）
- **X, Y**: 特征点在图像中的坐标

## 依赖项

```bash
pip install Pillow numpy matplotlib
```

## 标准参考

- ICAO Doc 9303: 机读旅行证件
- ISO/IEC 19794-5: 生物特征数据交换格式 - 面部图像数据
- ISO/IEC 7816-4: 智能卡应用标准

## 注意事项

1. 生成的 DG2 文件严格遵循 ICAO 9303 标准
2. 支持 JPEG 格式图像（JPEG2000 需要额外依赖）
3. 特征点坐标为近似值（实际应用需要专业的面部识别算法）
4. 生成的文件可用于测试和开发，但不应用于实际证件

## 故障排除

如果遇到中文显示问题（matplotlib 警告），可以：
1. 安装中文字体
2. 或忽略警告（不影响功能）

## 作者

DG2 Analysis Tools - 2025