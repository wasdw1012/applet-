"""
DG2严格验证补丁
根据ISO/IEC 19794-5和ICAO 9303标准的必要修改
"""

# 1. 修正的常量值（根据icao_dg2_strict.py）
CORRECTIONS = {
    # CBEFF头部版本标签必须是0xA1，不是0x80
    'ICAO_HEADER_VERSION_TAG': 0xA1,  # 原值可能是0x80
    
    # 格式类型必须是0x0008
    'FORMAT_TYPE_FACIAL': 0x0008,  # 原值可能是0x0005
    
    # 表情必须是0x0001（中性）
    'EXPRESSION_NEUTRAL': 0x0001,  # 原值可能是0x0000
    
    # 人脸图像类型必须是0x01（全正面）
    'FACE_IMAGE_TYPE': 0x01,  # 原值可能是0x00
    
    # 质量必须 >= 50，建议100
    'QUALITY_VALUE': 100,  # 原值可能是0
}

# 2. create_facial_record_header 函数必须返回正确的版本号
def create_facial_record_header_corrected():
    """修正的人脸记录头部"""
    header = b''
    header += b'FAC\x00'  # Format Identifier (4 bytes)
    header += b'010\x00'  # Version Number - 必须是 '010\x00' 不是 '0100'
    header += b'\x00\x00\x00\x00'  # Length (placeholder, 4 bytes)
    header += struct.pack('>H', 1)  # Number of Facial Images (2 bytes)
    return header

# 3. create_biometric_header_template 必须使用正确的CBEFF结构
def create_biometric_header_template_corrected():
    """根据icao_dg2_strict.py的CBEFF头部结构"""
    import struct
    
    # CBEFF内部各字段
    cbeff_content = b''
    
    # Patron Header Version (Tag 0xA1) - 值是0x01
    cbeff_content += encode_tlv(0xA1, bytes([0x01]))
    
    # BDB Format Owner (Tag 0x87) - 0x0101
    cbeff_content += encode_tlv(0x87, struct.pack('>H', 0x0101))
    
    # BDB Format Type (Tag 0x88) - 0x0008
    cbeff_content += encode_tlv(0x88, struct.pack('>H', 0x0008))
    
    # Biometric Type (Tag 0x81) - 0x02
    cbeff_content += encode_tlv(0x81, bytes([0x02]))
    
    # Biometric Subtype (Tag 0x82) - 0x00
    cbeff_content += encode_tlv(0x82, bytes([0x00]))
    
    # BDB Creation Date (Tag 0x85) - 7 bytes
    # 示例：2024年用BCD编码
    cbeff_content += encode_tlv(0x85, bytes([0x20, 0x24, 0x01, 0x01, 0x00, 0x00, 0x00]))
    
    # BDB Validity Period (Tag 0x86) - 8 bytes, 0xFF = no expiry
    cbeff_content += encode_tlv(0x86, bytes([0xFF] * 8))
    
    # Creator (Tag 0x89) - 18 bytes
    cbeff_content += encode_tlv(0x89, bytes(18))
    
    # 整个CBEFF头部用Tag 0xA1包装
    return encode_tlv(0xA1, cbeff_content)

# 4. create_facial_information 中需要修正的值
FACIAL_INFO_CORRECTIONS = {
    'expression_offset': 13,  # Expression字段的偏移
    'expression_value': 0x0001,  # 必须是中性表情
    
    'face_type_offset': 19,  # Face Image Type字段的偏移  
    'face_type_value': 0x01,  # 必须是全正面
    
    'quality_offset': 30,  # Quality字段的偏移
    'quality_value': 100,  # 高质量
}

# 5. encode_tlv函数（如果需要）
def encode_tlv(tag, value):
    """BER-TLV编码"""
    if tag > 0xFF:
        tag_bytes = struct.pack('>H', tag)
    else:
        tag_bytes = bytes([tag])
    
    length = len(value)
    if length < 0x80:
        length_bytes = bytes([length])
    elif length <= 0xFF:
        length_bytes = bytes([0x81, length])
    elif length <= 0xFFFF:
        length_bytes = struct.pack('>BH', 0x82, length)
    else:
        length_bytes = struct.pack('>BI', 0x84, length)
    
    return tag_bytes + length_bytes + value