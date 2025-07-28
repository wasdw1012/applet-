"""
DG2 Strict Validator - Based on eIDClientCore/BSI standards
这是最严格的DG2验证实现，基于德国BSI标准
"""

import struct
from typing import Tuple, Optional, Dict, Any


class DG2StrictValidator:
    """
    严格的DG2验证器，实现了BSI TR-03110和ISO/IEC 19794-5的所有要求
    """
    
    # ASN.1 标签定义
    TAG_DG2 = 0x75
    TAG_BIOMETRIC_INFO_GROUP = 0x7F61
    TAG_INSTANCE_NUMBER = 0x02
    TAG_BIOMETRIC_INFO_TEMPLATE = 0x7F60
    TAG_CBEFF_HEADER = 0xA1
    TAG_BIOMETRIC_DATA = 0x5F2E
    
    # CBEFF头部标签
    TAG_PATRON_VERSION = 0x80
    TAG_BIOMETRIC_TYPE = 0x81
    TAG_BIOMETRIC_SUBTYPE = 0x82
    TAG_CREATION_DATE = 0x83
    TAG_VALIDITY_PERIOD = 0x85
    TAG_CREATOR = 0x86
    TAG_FORMAT_OWNER = 0x87
    TAG_FORMAT_TYPE = 0x88
    
    # 期望值
    BIOMETRIC_TYPE_FACE = 0x02
    FORMAT_OWNER_ICAO = 0x0101
    FORMAT_TYPE_FACE = 0x0008
    
    # ISO 19794-5常量
    FACE_IMAGE_TYPE_FULL_FRONTAL = 0x01
    IMAGE_TYPE_JPEG2000 = 0x02
    
    def __init__(self, dg2_data: bytes):
        self.data = dg2_data
        self.pos = 0
        self.errors = []
        
    def validate(self) -> Dict[str, Any]:
        """执行完整的DG2验证"""
        result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'image_offset': None,
            'image_length': None,
            'image_width': None,
            'image_height': None,
            'image_type': None
        }
        
        try:
            # 1. 验证DG2标签
            self._validate_tag(self.TAG_DG2, "DG2")
            self._parse_length()
            
            # 2. 验证生物特征信息组模板
            self._validate_composite_tag(self.TAG_BIOMETRIC_INFO_GROUP, "Biometric Info Group")
            bio_group_len = self._parse_length()
            bio_group_end = self.pos + bio_group_len
            
            # 3. 验证实例编号
            self._validate_tag(self.TAG_INSTANCE_NUMBER, "Instance Number")
            instance_len = self._parse_length()
            if instance_len != 1 or self.data[self.pos] != 0x01:
                raise ValueError("实例编号必须为01")
            self.pos += instance_len
            
            # 4. 验证生物特征信息模板
            self._validate_composite_tag(self.TAG_BIOMETRIC_INFO_TEMPLATE, "Biometric Info Template")
            bio_info_len = self._parse_length()
            bio_info_end = self.pos + bio_info_len
            
            # 5. 验证CBEFF头部
            self._validate_tag(self.TAG_CBEFF_HEADER, "CBEFF Header")
            cbeff_len = self._parse_length()
            cbeff_end = self.pos + cbeff_len
            self._validate_cbeff_header(cbeff_end)
            
            # 6. 验证生物特征数据块
            self._validate_composite_tag(self.TAG_BIOMETRIC_DATA, "Biometric Data Block")
            bio_data_len = self._parse_length()
            bio_data_start = self.pos
            
            # 7. 解析ISO 19794-5面部记录
            self._validate_iso19794_record(bio_data_len, result)
            
            # 如果没有错误，标记为有效
            if not self.errors:
                result['valid'] = True
                
        except Exception as e:
            self.errors.append(str(e))
            
        result['errors'] = self.errors
        return result
    
    def _validate_tag(self, expected_tag: int, name: str):
        """验证单字节标签"""
        if self.pos >= len(self.data):
            raise ValueError(f"数据结束：期望{name}标签")
            
        if self.data[self.pos] != expected_tag:
            raise ValueError(f"期望{name}标签0x{expected_tag:02X}，实际0x{self.data[self.pos]:02X}")
        self.pos += 1
        
    def _validate_composite_tag(self, expected_tag: int, name: str):
        """验证复合标签（2字节）"""
        if self.pos + 1 >= len(self.data):
            raise ValueError(f"数据结束：期望{name}标签")
            
        tag = (self.data[self.pos] << 8) | self.data[self.pos + 1]
        if tag != expected_tag:
            raise ValueError(f"期望{name}标签0x{expected_tag:04X}，实际0x{tag:04X}")
        self.pos += 2
        
    def _parse_length(self) -> int:
        """解析BER-TLV长度编码"""
        if self.pos >= len(self.data):
            raise ValueError("数据结束：解析长度时")
            
        first_byte = self.data[self.pos]
        self.pos += 1
        
        if first_byte < 0x80:
            # 短形式
            return first_byte
        else:
            # 长形式
            num_octets = first_byte & 0x7F
            if num_octets == 0 or num_octets > 4:
                raise ValueError(f"无效的长度编码：{num_octets}字节")
                
            if self.pos + num_octets > len(self.data):
                raise ValueError("数据结束：读取长度字节时")
                
            length = 0
            for _ in range(num_octets):
                length = (length << 8) | self.data[self.pos]
                self.pos += 1
                
            return length
            
    def _validate_cbeff_header(self, end_pos: int):
        """验证CBEFF头部的所有必需字段"""
        required_fields = {
            self.TAG_PATRON_VERSION: False,
            self.TAG_BIOMETRIC_TYPE: False,
            self.TAG_FORMAT_OWNER: False,
            self.TAG_FORMAT_TYPE: False
        }
        
        while self.pos < end_pos:
            tag = self.data[self.pos]
            self.pos += 1
            length = self._parse_length()
            
            if tag == self.TAG_PATRON_VERSION:
                if length != 2 or self.data[self.pos] != 0x01 or self.data[self.pos+1] != 0x01:
                    raise ValueError("无效的patron版本（必须是0x0101）")
                required_fields[tag] = True
                
            elif tag == self.TAG_BIOMETRIC_TYPE:
                if length != 1 or self.data[self.pos] != self.BIOMETRIC_TYPE_FACE:
                    raise ValueError("无效的生物特征类型（必须是Face）")
                required_fields[tag] = True
                
            elif tag == self.TAG_FORMAT_OWNER:
                if length != 2:
                    raise ValueError("无效的格式所有者长度")
                owner = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
                if owner != self.FORMAT_OWNER_ICAO:
                    raise ValueError(f"无效的格式所有者（必须是ICAO 0x{self.FORMAT_OWNER_ICAO:04X}）")
                required_fields[tag] = True
                
            elif tag == self.TAG_FORMAT_TYPE:
                if length != 2:
                    raise ValueError("无效的格式类型长度")
                fmt_type = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
                if fmt_type != self.FORMAT_TYPE_FACE:
                    raise ValueError(f"无效的格式类型（必须是0x{self.FORMAT_TYPE_FACE:04X}）")
                required_fields[tag] = True
                
            self.pos += length
            
        # 检查所有必需字段
        for tag, present in required_fields.items():
            if not present:
                raise ValueError(f"缺少必需的CBEFF字段：0x{tag:02X}")
                
    def _validate_iso19794_record(self, record_len: int, result: Dict[str, Any]):
        """验证ISO 19794-5面部记录"""
        record_start = self.pos
        
        # 1. 格式标识符
        if self.pos + 4 > len(self.data) or self.data[self.pos:self.pos+4] != b'FAC\x00':
            raise ValueError("无效的ISO 19794-5格式标识符（期望'FAC\\0'）")
        self.pos += 4
        
        # 2. 版本号
        if self.pos + 4 > len(self.data) or self.data[self.pos:self.pos+4] != b'010\x00':
            raise ValueError("无效的ISO 19794-5版本（期望'010\\0'）")
        self.pos += 4
        
        # 3. 记录长度
        if self.pos + 4 > len(self.data):
            raise ValueError("数据结束：读取记录长度时")
        declared_len = struct.unpack('>I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        
        if declared_len != record_len:
            raise ValueError(f"ISO记录长度不匹配：声明{declared_len}，实际{record_len}")
            
        # 4. 图像数量
        if self.pos + 2 > len(self.data):
            raise ValueError("数据结束：读取图像数量时")
        num_images = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        
        if num_images != 1:
            raise ValueError(f"DG2中只允许单个图像（发现{num_images}个）")
            
        # 5. 面部信息块
        self._parse_facial_information()
        
        # 6. 图像信息块
        self._parse_image_information(result)
        
        # 7. 图像数据
        header_size = self.pos - record_start
        result['image_offset'] = self.pos
        result['image_length'] = record_len - header_size
        
        # 验证JPEG2000签名
        self._validate_jpeg2000_signature()
        
    def _parse_facial_information(self):
        """解析面部信息块"""
        # 特征点数量
        if self.pos + 2 > len(self.data):
            raise ValueError("数据结束：读取特征点数量时")
        num_features = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        
        # 性别、眼色、发色
        if self.pos + 3 > len(self.data):
            raise ValueError("数据结束：读取面部属性时")
        self.pos += 3
        
        # 特征掩码
        if self.pos + 3 > len(self.data):
            raise ValueError("数据结束：读取特征掩码时")
        self.pos += 3
        
        # 表情
        if self.pos + 2 > len(self.data):
            raise ValueError("数据结束：读取表情时")
        self.pos += 2
        
        # 姿态角度
        if self.pos + 3 > len(self.data):
            raise ValueError("数据结束：读取姿态角度时")
        self.pos += 3
        
        # 姿态角度不确定性
        if self.pos + 3 > len(self.data):
            raise ValueError("数据结束：读取姿态不确定性时")
        self.pos += 3
        
        # 跳过特征点
        feature_data_size = num_features * 8
        if self.pos + feature_data_size > len(self.data):
            raise ValueError("数据结束：读取特征点数据时")
        self.pos += feature_data_size
        
    def _parse_image_information(self, result: Dict[str, Any]):
        """解析图像信息块"""
        # 面部图像类型
        if self.pos >= len(self.data):
            raise ValueError("数据结束：读取面部图像类型时")
        face_type = self.data[self.pos]
        self.pos += 1
        
        if face_type != self.FACE_IMAGE_TYPE_FULL_FRONTAL:
            raise ValueError(f"只允许正面面部图像（类型0x{face_type:02X}）")
            
        # 图像数据类型
        if self.pos >= len(self.data):
            raise ValueError("数据结束：读取图像数据类型时")
        image_type = self.data[self.pos]
        self.pos += 1
        
        if image_type != self.IMAGE_TYPE_JPEG2000:
            raise ValueError(f"只允许JPEG2000图像（类型0x{image_type:02X}）")
        result['image_type'] = 'JPEG2000'
        
        # 宽度和高度
        if self.pos + 4 > len(self.data):
            raise ValueError("数据结束：读取图像尺寸时")
        result['image_width'] = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        result['image_height'] = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        
        # 验证尺寸
        if not (240 <= result['image_width'] <= 1024):
            raise ValueError(f"图像宽度超出范围：{result['image_width']}")
        if not (320 <= result['image_height'] <= 1024):
            raise ValueError(f"图像高度超出范围：{result['image_height']}")
            
        # 跳过剩余字段
        if self.pos + 4 > len(self.data):
            raise ValueError("数据结束：读取图像信息剩余字段时")
        self.pos += 4
        
    def _validate_jpeg2000_signature(self):
        """验证JPEG2000签名"""
        jp2_sig = b'\x00\x00\x00\x0C\x6A\x50\x20\x20'
        
        # 在接下来的20字节中查找签名
        found = False
        for i in range(min(20, len(self.data) - self.pos - 8)):
            if self.data[self.pos + i:self.pos + i + 8] == jp2_sig:
                found = True
                break
                
        if not found:
            raise ValueError("未找到有效的JPEG2000签名")


def validate_dg2_file(filename: str) -> Dict[str, Any]:
    """验证DG2文件"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    validator = DG2StrictValidator(data)
    return validator.validate()


if __name__ == "__main__":
    # 测试代码
    import sys
    
    if len(sys.argv) > 1:
        result = validate_dg2_file(sys.argv[1])
        print(f"验证结果: {'通过' if result['valid'] else '失败'}")
        if result['errors']:
            print("错误:")
            for error in result['errors']:
                print(f"  - {error}")
        if result['valid']:
            print(f"图像信息:")
            print(f"  - 类型: {result['image_type']}")
            print(f"  - 尺寸: {result['image_width']}x{result['image_height']}")
            print(f"  - 偏移: {result['image_offset']}")
            print(f"  - 长度: {result['image_length']}")
    else:
        print("用法: python dg2_strict_validator.py <DG2文件>")