#!/usr/bin/env python3
"""
PyMRTD 兼容的 DG2 生成实现
严格遵循 ICAO 9303 Part 10 标准
"""

import struct
from datetime import datetime

# ICAO 9303 标准的 DG2 标签定义
DG2_TAG = 0x75                                    # Data Group 2
BIOMETRIC_INFO_GROUP_TEMPLATE_TAG = 0x7F61        # 生物特征信息组模板
NUMBER_OF_INSTANCES_TAG = 0x02                    # 生物特征实例数量
BIOMETRIC_INFO_TEMPLATE_TAG = 0x7F60              # 生物特征信息模板（每个实例）
BIOMETRIC_HEADER_TEMPLATE_TAG = 0xA1              # 生物特征头模板
BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E                 # 生物特征数据块
STANDARD_BIOMETRIC_HEADER_TAG = 0x7F2E            # 标准生物特征头（可选）

# 生物特征头部内的标签
ICAO_HEADER_VERSION_TAG = 0x80                    # ICAO 头版本
BIOMETRIC_TYPE_TAG = 0x81                         # 生物特征类型
BIOMETRIC_SUBTYPE_TAG = 0x82                      # 生物特征子类型
CREATION_DATE_TIME_TAG = 0x83                     # 创建日期时间
VALIDITY_PERIOD_TAG = 0x85                        # 有效期
CREATOR_TAG = 0x86                                # 创建者
FORMAT_OWNER_TAG = 0x87                           # 格式所有者
FORMAT_TYPE_TAG = 0x88                            # 格式类型

# 生物特征类型定义
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02             # 面部特征
BIOMETRIC_SUBTYPE_NO_SUBTYPE = 0x00               # 无子类型

# 格式定义
FACIAL_RECORD_DATA_FORMAT_OWNER = 0x0101          # ISO/IEC JTC1/SC37
FACIAL_RECORD_DATA_FORMAT_TYPE = 0x0001           # 通用面部图像格式


def encode_length(length):
    """编码 ASN.1 长度"""
    if length < 128:
        return bytes([length])
    
    # 长形式
    length_bytes = []
    temp = length
    while temp > 0:
        length_bytes.insert(0, temp & 0xFF)
        temp >>= 8
    
    return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)


def encode_tlv(tag, value):
    """编码 TLV 结构"""
    if isinstance(tag, int):
        if tag < 256:
            tag_bytes = bytes([tag])
        else:
            # 双字节标签
            tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
    else:
        tag_bytes = tag
    
    if isinstance(value, int):
        value = bytes([value])
    elif not isinstance(value, bytes):
        value = bytes(value)
    
    length_bytes = encode_length(len(value))
    return tag_bytes + length_bytes + value


def create_biometric_header_template():
    """创建生物特征头模板"""
    # ICAO 头版本 (0x00 = 版本 0)
    icao_version = encode_tlv(ICAO_HEADER_VERSION_TAG, b'\x00')
    
    # 生物特征类型 - 面部特征
    biometric_type = encode_tlv(BIOMETRIC_TYPE_TAG, bytes([BIOMETRIC_TYPE_FACIAL_FEATURES]))
    
    # 生物特征子类型 - 无子类型
    biometric_subtype = encode_tlv(BIOMETRIC_SUBTYPE_TAG, bytes([BIOMETRIC_SUBTYPE_NO_SUBTYPE]))
    
    # 创建日期时间 (YYMMDDHHMMSS 格式)
    now = datetime.now()
    date_str = now.strftime("%y%m%d%H%M%S").encode('ascii')
    creation_date = encode_tlv(CREATION_DATE_TIME_TAG, date_str)
    
    # 有效期 (YYYYMMDD 到 YYYYMMDD)
    validity_from = now.strftime("%Y%m%d").encode('ascii')
    validity_to = (now.year + 10)  # 10年有效期
    validity_to_str = f"{validity_to:04d}{now.month:02d}{now.day:02d}".encode('ascii')
    validity_period = encode_tlv(VALIDITY_PERIOD_TAG, validity_from + validity_to_str)
    
    # 创建者 (PID，16字节)
    creator = encode_tlv(CREATOR_TAG, b'ICAO9303DG2GEN00')
    
    # 格式所有者和类型
    format_owner = encode_tlv(FORMAT_OWNER_TAG, struct.pack('>H', FACIAL_RECORD_DATA_FORMAT_OWNER))
    format_type = encode_tlv(FORMAT_TYPE_TAG, struct.pack('>H', FACIAL_RECORD_DATA_FORMAT_TYPE))
    
    # 组装生物特征头模板
    header_content = (icao_version + biometric_type + biometric_subtype + 
                     creation_date + validity_period + creator + 
                     format_owner + format_type)
    
    return encode_tlv(BIOMETRIC_HEADER_TEMPLATE_TAG, header_content)


def create_biometric_data_block(image_data):
    """创建生物特征数据块"""
    return encode_tlv(BIOMETRIC_DATA_BLOCK_TAG, image_data)


def create_dg2_pymrtd_compatible(image_data):
    """
    创建符合 PyMRTD 验证要求的 DG2 结构
    
    完整结构：
    75 (DG2)
    └── 7F61 (生物特征信息组模板)
        ├── 02 (生物特征实例数量)
        │   └── 01 (数量值：1)
        └── 7F60 (生物特征信息模板)
            ├── A1 (生物特征头模板)
            │   ├── 80 (ICAO头版本)
            │   ├── 81 (生物特征类型)
            │   ├── 82 (生物特征子类型)
            │   ├── 83 (创建日期时间)
            │   ├── 85 (有效期)
            │   ├── 86 (创建者)
            │   ├── 87 (格式所有者)
            │   └── 88 (格式类型)
            └── 5F2E (生物特征数据块)
                └── [JPEG2000图像数据]
    """
    
    # 1. 创建生物特征头模板
    biometric_header = create_biometric_header_template()
    
    # 2. 创建生物特征数据块
    biometric_data = create_biometric_data_block(image_data)
    
    # 3. 创建生物特征信息模板 (7F60)
    # 注意：这是 PyMRTD 可能期望的额外层
    biometric_info_content = biometric_header + biometric_data
    biometric_info_template = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, biometric_info_content)
    
    # 4. 创建生物特征实例数量 (02)
    number_of_instances = encode_tlv(NUMBER_OF_INSTANCES_TAG, b'\x01')
    
    # 5. 创建生物特征信息组模板 (7F61)
    # 包含：实例数量 + 生物特征信息模板
    biometric_info_group_content = number_of_instances + biometric_info_template
    biometric_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, biometric_info_group_content)
    
    # 6. 创建 DG2 (75)
    dg2 = encode_tlv(DG2_TAG, biometric_info_group)
    
    return dg2


def create_dg2_alternative_structure(image_data):
    """
    备选结构（如果上面的不工作）
    
    75 (DG2)
    └── 7F61 (生物特征信息组模板)
        ├── 02 (生物特征实例数量)
        │   └── 01 (数量值：1)
        ├── A1 (生物特征头模板)
        │   └── [头信息]
        └── 5F2E (生物特征数据块)
            └── [JPEG2000图像数据]
    """
    
    # 1. 创建生物特征头模板
    biometric_header = create_biometric_header_template()
    
    # 2. 创建生物特征数据块
    biometric_data = create_biometric_data_block(image_data)
    
    # 3. 创建生物特征实例数量
    number_of_instances = encode_tlv(NUMBER_OF_INSTANCES_TAG, b'\x01')
    
    # 4. 创建生物特征信息组模板 (直接包含所有元素)
    biometric_info_group_content = number_of_instances + biometric_header + biometric_data
    biometric_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, biometric_info_group_content)
    
    # 5. 创建 DG2
    dg2 = encode_tlv(DG2_TAG, biometric_info_group)
    
    return dg2


def test_dg2_structure():
    """测试 DG2 结构生成"""
    # 模拟的 JPEG2000 图像数据
    test_image_data = b'\xFF\x4F\xFF\x51' + b'\x00' * 100  # JP2 signature + dummy data
    
    # 生成主要结构
    dg2_main = create_dg2_pymrtd_compatible(test_image_data)
    print("主要结构（包含 7F60）:")
    print_hex_dump(dg2_main[:100])  # 只打印前100字节
    
    # 生成备选结构
    dg2_alt = create_dg2_alternative_structure(test_image_data)
    print("\n备选结构（不含 7F60）:")
    print_hex_dump(dg2_alt[:100])


def print_hex_dump(data):
    """打印十六进制转储"""
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        print(f'{i:04X}: {hex_part}')


if __name__ == "__main__":
    test_dg2_structure()
    
    # 使用说明
    print("\n使用方法:")
    print("1. 如果 PyMRTD 报错 '期望 7F60'，使用 create_dg2_pymrtd_compatible()")
    print("2. 如果 PyMRTD 报错 '期望 A1'，使用 create_dg2_alternative_structure()")
    print("3. 两种结构的主要区别是是否包含 7F60 (生物特征信息模板) 层")