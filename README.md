# Passport DG2 Reader for ACR122U

使用ACR122U读卡器读取电子护照DG2数据（面部照片）的Python实现。

## 功能特性

- BAC (Basic Access Control) 认证
- MRZ密钥派生（符合ICAO 9303标准）
- DG2数据读取和解析
- 自动提取护照照片

## 安装依赖

```bash
pip install pyscard pycryptodome
```

## 使用方法

1. 修改 `read_passport_dg2.py` 中的MRZ信息：
   - `DOCUMENT_NUMBER`: 护照号（9位）
   - `DATE_OF_BIRTH`: 出生日期（YYMMDD格式）
   - `DATE_OF_EXPIRY`: 有效期（YYMMDD格式）

2. 连接ACR122U读卡器并放置护照

3. 运行脚本：
   ```bash
   python read_passport_dg2.py
   ```

## 输出文件

- `dg2_raw.bin`: 原始DG2数据（TLV格式）
- `passport_photo.jpg`: 提取的护照照片

## 注意事项

- 需要ACR122U或兼容的NFC读卡器
- 护照必须支持BAC认证
- MRZ信息必须准确无误

## DG2数据结构

```
Tag 0x75 (DG2)
└── Tag 0x7F61 (Biometric Information Group)
    └── Tag 0x7F60 (Biometric Information Template)
        └── Tag 0x5F2E (Biometric Data Block)
            └── JPEG/JPEG2000 Image
```