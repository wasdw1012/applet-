#!/usr/bin/env python3
"""
专业十六进制解析工具 - 纯解析版本
支持多种格式的深度解析，无核验功能
"""

import sys
import os
import struct
import re
import json
import hashlib
import math
import binascii
import mmap
import base64
from typing import Optional, Tuple, List, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter, OrderedDict
from datetime import datetime
import io

# 颜色代码
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    BLACK = '\033[30m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'
    BG_RED = '\033[41m'

class FileFormat(Enum):
    """已知文件格式"""
    UNKNOWN = "未知"
    JPEG = "JPEG图像"
    PNG = "PNG图像" 
    GIF = "GIF图像"
    BMP = "BMP图像"
    JPEG2000 = "JPEG2000/JP2图像"
    DER = "DER编码"
    PEM = "PEM编码"
    FAC = "FAC人脸数据"
    TLV = "TLV结构"
    PASSPORT_DG = "护照数据组"
    ZIP = "ZIP压缩"
    PDF = "PDF文档"
    PKCS7 = "PKCS#7/CMS"
    PKCS8 = "PKCS#8私钥"
    PKCS1 = "PKCS#1密钥"
    X509 = "X.509证书"

@dataclass
class ParsedField:
    """通用解析字段"""
    name: str
    offset: int
    length: int
    raw_value: bytes
    parsed_value: Any = None
    type_hint: str = ""
    children: List['ParsedField'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_display_value(self) -> str:
        """获取显示值"""
        if self.parsed_value is not None:
            return str(self.parsed_value)
        elif len(self.raw_value) <= 16:
            return self.raw_value.hex().upper()
        else:
            return f"{self.raw_value[:8].hex().upper()}...({len(self.raw_value)} bytes)"

@dataclass
class TLVField:
    """TLV字段信息"""
    tag: int
    tag_bytes: bytes
    length: int
    length_bytes: bytes
    value: bytes
    offset: int
    level: int = 0
    tag_name: str = ""
    tag_description: str = ""
    children: List['TLVField'] = field(default_factory=list)
    parsed_value: Any = None
    value_type: str = ""
    is_truncated: bool = False  # 数据是否被截断
    expected_length: int = 0    # 期望长度（用于截断时）

class HexAnalyzer:
    """专业十六进制解析器"""
    
    # 护照数据组标签
    PASSPORT_TAGS = {
        0x60: ("COM", "通用数据元素"),
        0x61: ("DG1", "MRZ数据"),
        0x63: ("DG3", "指纹"),
        0x65: ("DG5", "人像显示"),
        0x67: ("DG7", "签名"),
        0x68: ("DG8", "数据特征"),
        0x69: ("DG9", "结构特征"),
        0x6B: ("DG11", "个人详细信息"),
        0x6C: ("DG12", "文档详细信息"),
        0x6D: ("DG13", "可选详细信息"),
        0x6E: ("DG14", "芯片认证公钥"),
        0x6F: ("DG15", "主动认证公钥"),
        0x70: ("DG16", "联系人"),
        0x75: ("DG2", "面部生物特征"),
        0x77: ("SOD", "安全对象文档"),
        32608: ("BIT", "生物信息模板"),            # 0x7F60
        32609: ("BIT_GROUP", "生物信息组模板"),     # 0x7F61
        24321: ("MRZ_DATA", "MRZ数据内容"),         # 0x5F01
        24323: ("DATE_OF_EXPIRY", "有效期"),        # 0x5F03
        24324: ("DATE_OF_BIRTH", "出生日期"),       # 0x5F04
        24325: ("DOCUMENT_NUMBER", "文档号"),       # 0x5F05
        24326: ("NATIONALITY", "国籍"),            # 0x5F06
        24327: ("SEX", "性别"),                     # 0x5F07
        24334: ("NAME", "姓名"),                    # 0x5F0E
        24366: ("BDB", "生物数据块"),               # 0x5F2E
        0xA1: ("BHT", "生物头模板"),
    }
    
    # ASN.1 通用标签
    ASN1_TAGS = {
        0x01: ("BOOLEAN", "布尔值"),
        0x02: ("INTEGER", "整数"),
        0x03: ("BIT_STRING", "位串"),
        0x04: ("OCTET_STRING", "字节串"),
        0x05: ("NULL", "空值"),
        0x06: ("OID", "对象标识符"),
        0x0A: ("ENUMERATED", "枚举"),
        0x0C: ("UTF8String", "UTF-8字符串"),
        0x13: ("PrintableString", "可打印字符串"),
        0x14: ("T61String", "T61字符串"),
        0x16: ("IA5String", "IA5字符串"),
        0x17: ("UTCTime", "UTC时间"),
        0x18: ("GeneralizedTime", "通用时间"),
        0x30: ("SEQUENCE", "序列"),
        0x31: ("SET", "集合"),
        0xA0: ("CONTEXT_0", "上下文特定[0]"),
        0xA1: ("CONTEXT_1", "上下文特定[1]"),
        0xA2: ("CONTEXT_2", "上下文特定[2]"),
        0xA3: ("CONTEXT_3", "上下文特定[3]"),
    }
    
    # BHT字段标签
    BHT_TAGS = {
        0x80: ("ICAO_VERSION", "ICAO版本"),
        0x81: ("BIOMETRIC_TYPE", "生物特征类型"),
        0x82: ("BIOMETRIC_SUBTYPE", "生物特征子类型"),
        0x83: ("CREATE_DATETIME", "创建日期时间"),
        0x84: ("VALIDITY_PERIOD", "有效期"),
        0x85: ("CREATOR_PID", "创建者PID"),
        0x86: ("FORMAT_OWNER", "格式所有者"),
        0x87: ("FORMAT_TYPE", "格式类型"),
        0x88: ("QUALITY", "质量"),
    }
    
    # 生物特征类型
    BIOMETRIC_TYPES = {
        0x00: "未指定",
        0x01: "过滤的多光谱图像",
        0x02: "面部特征",
        0x03: "指纹",
        0x04: "虹膜",
        0x05: "视网膜",
        0x06: "手形",
        0x07: "签名",
        0x08: "按键动态",
        0x09: "唇动",
        0x0A: "热成像面部",
        0x0B: "热成像手",
        0x0C: "步态",
        0x0D: "体味",
        0x0E: "DNA",
        0x0F: "耳形",
        0x10: "手指形状",
        0x11: "掌纹",
        0x12: "静脉图案",
    }
    
    # JP2盒子类型
    JP2_BOX_TYPES = {
        b'jP  ': "JP2签名盒",
        b'ftyp': "文件类型盒",
        b'jp2h': "JP2头部盒",
        b'ihdr': "图像头部盒",
        b'colr': "颜色规范盒",
        b'jp2c': "码流盒",
        b'res ': "分辨率盒",
        b'resc': "捕获分辨率盒",
        b'resd': "默认显示分辨率盒",
    }
    
    # 已知OID映射
    OID_MAP = {
        "1.2.840.113549.1.1.1": "RSA加密",
        "1.2.840.113549.1.1.5": "SHA1withRSA",
        "1.2.840.113549.1.1.11": "SHA256withRSA",
        "1.2.840.113549.1.7.2": "PKCS#7签名数据",
        "1.2.840.113549.1.9.3": "内容类型",
        "1.2.840.113549.1.9.4": "消息摘要",
        "1.2.840.113549.1.9.5": "签名时间",
        "2.5.4.3": "通用名称(CN)",
        "2.5.4.6": "国家(C)",
        "2.5.4.7": "地区(L)",
        "2.5.4.10": "组织(O)",
        "2.5.4.11": "组织单位(OU)",
        "2.5.29.14": "主体密钥标识符",
        "2.5.29.15": "密钥用途",
        "2.5.29.19": "基本约束",
        "2.5.29.35": "授权密钥标识符",
        "2.23.136.1.1.1": "ICAO护照",
        "2.23.136.1.1.6.1": "文档签名者",
        "2.23.136.1.1.6.2": "国家签名证书颁发机构",
    }
    
    def __init__(self, filepath: str, use_mmap: bool = True):
        self.filepath = filepath
        self.use_mmap = use_mmap
        self.file_handle = None
        self.mmap_handle = None
        self.data = None
        self._open_file()
        self.filesize = len(self.data)
        self.format = self._detect_format()
        self.encoding_cache = {}  # 缓存编码检测结果
        
    def _open_file(self):
        """打开文件（支持内存映射）"""
        try:
            self.file_handle = open(self.filepath, 'rb')
            self.filesize = os.path.getsize(self.filepath)
            
            # 对于大文件使用内存映射
            if self.use_mmap and self.filesize > 1024 * 1024:  # 大于1MB
                try:
                    self.mmap_handle = mmap.mmap(self.file_handle.fileno(), 0, access=mmap.ACCESS_READ)
                    self.data = self.mmap_handle
                    print(f"{Colors.GREEN}使用内存映射模式 (文件大小: {self.filesize/1024/1024:.2f} MB){Colors.RESET}")
                except:
                    # 如果mmap失败，回退到普通读取
                    self.data = self.file_handle.read()
                    self.file_handle.seek(0)
            else:
                # 小文件直接读取
                self.data = self.file_handle.read()
                self.file_handle.seek(0)
                
        except FileNotFoundError:
            print(f"{Colors.RED}错误：文件 '{self.filepath}' 未找到{Colors.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}打开文件错误: {e}{Colors.RESET}")
            sys.exit(1)
            
    def __del__(self):
        """清理资源"""
        if self.mmap_handle:
            self.mmap_handle.close()
        if self.file_handle:
            self.file_handle.close()
    
    def _detect_format(self) -> FileFormat:
        """智能检测文件格式（支持PEM预处理）"""
        if len(self.data) < 4:
            return FileFormat.UNKNOWN
            
        # 检查文件头
        header = self.data[:20]
        
        # PEM格式检测和预处理
        if header.startswith(b'-----BEGIN'):
            # 先标记为PEM
            original_format = FileFormat.PEM
            # 解码PEM为DER
            if self._decode_pem():
                # 重新检测格式
                header = self.data[:20]
            else:
                return original_format
        
        # 图像格式
        if header[:3] == b'\xFF\xD8\xFF':
            return FileFormat.JPEG
        if header[:8] == b'\x89PNG\r\n\x1a\n':
            return FileFormat.PNG
        if header[:6] in [b'GIF87a', b'GIF89a']:
            return FileFormat.GIF
        if header[:2] == b'BM':
            return FileFormat.BMP
        if header[4:12] == b'jP  \r\n\x87\n' or header[4:8] == b'ftyp':
            return FileFormat.JPEG2000
            
        # 护照人脸格式
        if header[:4] == b'FAC\x00':
            return FileFormat.FAC
            
        # 压缩格式
        if header[:4] == b'PK\x03\x04':
            return FileFormat.ZIP
            
        # 文档格式
        if header[:4] == b'%PDF':
            return FileFormat.PDF
            
        # ASN.1/DER格式检测
        if header[0] == 0x30:
            # 检查是否是证书
            if self._looks_like_certificate():
                return FileFormat.X509
            # 检查是否是PKCS#7
            if self._looks_like_pkcs7():
                return FileFormat.PKCS7
            # 检查是否是私钥
            if self._looks_like_private_key():
                return self._detect_key_format()
            return FileFormat.DER
            
        # 护照数据组
        if header[0] in self.PASSPORT_TAGS:
            return FileFormat.PASSPORT_DG
            
        # TLV结构检测
        if self._looks_like_tlv():
            return FileFormat.TLV
            
        return FileFormat.UNKNOWN
        
    def _decode_pem(self) -> bool:
        """解码PEM格式为DER"""
        try:
            # 查找PEM边界
            pem_data = self.data
            if isinstance(pem_data, mmap.mmap):
                pem_data = bytes(pem_data)
                
            pem_str = pem_data.decode('ascii', errors='ignore')
            
            # 提取Base64内容
            begin_marker = '-----BEGIN'
            end_marker = '-----END'
            
            begin_pos = pem_str.find(begin_marker)
            if begin_pos == -1:
                return False
                
            # 找到第一行结束
            line_end = pem_str.find('\n', begin_pos)
            if line_end == -1:
                return False
                
            # 找到结束标记
            end_pos = pem_str.find(end_marker, line_end)
            if end_pos == -1:
                return False
                
            # 提取Base64数据
            base64_data = pem_str[line_end:end_pos].strip()
            # 移除所有空白字符
            base64_data = ''.join(base64_data.split())
            
            # 解码Base64
            der_data = base64.b64decode(base64_data)
            
            # 替换数据
            self.data = der_data
            self.filesize = len(der_data)
            
            # 如果之前使用mmap，需要关闭
            if self.mmap_handle:
                self.mmap_handle.close()
                self.mmap_handle = None
                
            print(f"{Colors.GREEN}PEM格式已解码为DER ({len(der_data)} 字节){Colors.RESET}")
            return True
            
        except Exception as e:
            print(f"{Colors.YELLOW}PEM解码失败: {e}{Colors.RESET}")
            return False
    
    def _looks_like_certificate(self) -> bool:
        """检查是否像X.509证书"""
        try:
            # 证书通常包含版本号和序列号
            if len(self.data) > 50:
                # 查找常见的证书OID
                return b'\x55\x04\x03' in self.data[:200]  # CN OID
        except:
            pass
        return False
    
    def _looks_like_pkcs7(self) -> bool:
        """检查是否像PKCS#7"""
        try:
            # PKCS#7 OID: 1.2.840.113549.1.7.2
            return b'\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02' in self.data[:50]
        except:
            pass
        return False
    
    def _looks_like_private_key(self) -> bool:
        """检查是否像私钥"""
        try:
            # 私钥通常以版本号0开始
            if len(self.data) > 10 and self.data[0] == 0x30:
                # 查找INTEGER标签
                return self.data[4:6] == b'\x02\x01\x00'  # version 0
        except:
            pass
        return False
    
    def _detect_key_format(self) -> FileFormat:
        """检测密钥格式"""
        # 检查PKCS#8 OID
        if b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01' in self.data[:50]:
            return FileFormat.PKCS8
        return FileFormat.PKCS1
    
    def _looks_like_tlv(self) -> bool:
        """检查是否像TLV结构"""
        try:
            offset = 0
            parsed_count = 0
            while offset < min(100, len(self.data)) and parsed_count < 3:
                tag, tag_len, _ = self._read_tag(offset)
                if tag is None:
                    break
                length, length_len, _ = self._read_length(offset + tag_len)
                if length is None or length > len(self.data) - offset:
                    break
                offset += tag_len + length_len + length
                parsed_count += 1
            return parsed_count >= 2
        except:
            return False
    
    def _read_tag(self, offset: int) -> Tuple[Optional[int], int, bytes]:
        """读取TLV标签（支持多字节，处理截断）"""
        if offset >= len(self.data):
            return None, 0, b''
            
        first_byte = self.data[offset]
        
        # 单字节标签
        if (first_byte & 0x1F) != 0x1F:
            return first_byte, 1, bytes([first_byte])
        
        # 多字节标签
        tag_bytes = [first_byte]
        pos = offset + 1
        while pos < len(self.data):
            byte = self.data[pos]
            tag_bytes.append(byte)
            pos += 1
            if (byte & 0x80) == 0:
                break
        
        # 检查标签是否被截断
        if pos >= len(self.data) and len(tag_bytes) > 1 and (tag_bytes[-1] & 0x80) != 0:
            # 标签被截断，返回None表示错误
            return None, 0, b''
                
        # 转换为整数
        tag = 0
        for b in tag_bytes:
            tag = (tag << 8) | b
            
        return tag, len(tag_bytes), bytes(tag_bytes)
    
    def _read_length(self, offset: int) -> Tuple[Optional[int], int, bytes]:
        """读取BER-TLV长度（支持长格式和不定长）"""
        if offset >= len(self.data):
            return None, 0, b''
            
        first_byte = self.data[offset]
        
        # 短格式
        if first_byte & 0x80 == 0:
            return first_byte, 1, bytes([first_byte])
        
        # 长格式
        length_bytes = first_byte & 0x7F
        if length_bytes == 0:
            # 不定长编码 (0x80)
            return -1, 1, bytes([first_byte])  # 返回-1表示不定长
            
        if offset + 1 + length_bytes > len(self.data):
            return None, 0, b''
            
        length = 0
        length_data = bytes([first_byte])
        for i in range(length_bytes):
            byte = self.data[offset + 1 + i]
            length = (length << 8) | byte
            length_data += bytes([byte])
            
        return length, 1 + length_bytes, length_data
    
    def detect_encoding(self, data: bytes) -> str:
        """智能检测文本编码"""
        # 缓存检查
        data_hash = hash(data)
        if data_hash in self.encoding_cache:
            return self.encoding_cache[data_hash]
            
        encodings = ['utf-8', 'utf-16', 'utf-16-be', 'utf-16-le', 
                    'gbk', 'gb18030', 'big5', 'shift_jis', 
                    'iso-8859-1', 'windows-1252']
        
        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                # 检查是否包含无效字符
                if '\x00' not in decoded and '\ufffd' not in decoded:
                    self.encoding_cache[data_hash] = encoding
                    return encoding
            except:
                continue
                
        self.encoding_cache[data_hash] = 'ascii'
        return 'ascii'
    
    def parse_bcd(self, data: bytes) -> str:
        """解析BCD编码"""
        result = ""
        for byte in data:
            high = (byte >> 4) & 0x0F
            low = byte & 0x0F
            if high <= 9:
                result += str(high)
            if low <= 9:
                result += str(low)
        return result
    
    def parse_datetime(self, data: bytes, format_type: str = "auto") -> Optional[datetime]:
        """解析各种日期时间格式"""
        if not data:
            return None
            
        try:
            if format_type == "auto":
                # 自动检测格式
                if len(data) == 6:  # YYMMDD
                    format_type = "yymmdd"
                elif len(data) == 7:  # YYMMDDhhmmss (BCD)
                    format_type = "bcd"
                elif len(data) == 8:  # YYYYMMDD
                    format_type = "yyyymmdd"
                elif len(data) in [13, 15]:  # ASN.1时间
                    format_type = "asn1"
            
            if format_type == "bcd":
                # BCD编码的日期时间
                date_str = self.parse_bcd(data)
                if len(date_str) >= 12:
                    return datetime.strptime(date_str[:12], "%y%m%d%H%M%S")
                elif len(date_str) >= 6:
                    return datetime.strptime(date_str[:6], "%y%m%d")
                    
            elif format_type == "yymmdd":
                date_str = data.decode('ascii', errors='ignore')
                return datetime.strptime(date_str, "%y%m%d")
                
            elif format_type == "yyyymmdd":
                date_str = data.decode('ascii', errors='ignore')
                return datetime.strptime(date_str, "%Y%m%d")
                
            elif format_type == "asn1":
                # ASN.1 UTCTime或GeneralizedTime
                date_str = data.decode('ascii', errors='ignore').rstrip('Z')
                if len(date_str) == 12:  # YYMMDDhhmmss
                    return datetime.strptime(date_str, "%y%m%d%H%M%S")
                elif len(date_str) == 14:  # YYYYMMDDhhmmss
                    return datetime.strptime(date_str, "%Y%m%d%H%M%S")
                    
        except Exception as e:
            pass
            
        return None
    
    def analyze_tlv(self, data: bytes = None, offset: int = 0, max_depth: int = 10, 
                    level: int = 0, context_hint: str = "", base_file_offset: int = 0) -> List[TLVField]:
        """深度解析TLV结构（支持绝对偏移量、不定长编码和截断处理）"""
        if data is None:
            data = self.data
            base_file_offset = 0
            
        fields = []
        current_offset = offset
        
        while current_offset < len(data) and level < max_depth:
            # 计算文件中的绝对偏移量
            absolute_offset = base_file_offset + current_offset
            
            # 读取标签
            tag, tag_len, tag_bytes = self._read_tag(current_offset)
            if tag is None:
                # 标签被截断，创建错误记录
                if current_offset < len(data):
                    error_field = TLVField(
                        tag=0,
                        tag_bytes=data[current_offset:current_offset+1],
                        length=0,
                        length_bytes=b'',
                        value=b'',
                        offset=absolute_offset,
                        level=level,
                        tag_name="TRUNCATED_TAG",
                        tag_description="标签被截断",
                        is_truncated=True
                    )
                    fields.append(error_field)
                break
                
            # 读取长度
            length, length_len, length_bytes = self._read_length(current_offset + tag_len)
            if length is None:
                break
                
            # 处理不定长编码
            if length == -1:
                # 查找EOC (End-of-Contents: 00 00)
                eoc_pos = data.find(b'\x00\x00', current_offset + tag_len + length_len)
                if eoc_pos == -1:
                    # 未找到EOC，使用剩余数据
                    length = len(data) - (current_offset + tag_len + length_len)
                else:
                    length = eoc_pos - (current_offset + tag_len + length_len)
                    
            # 读取值
            value_offset = current_offset + tag_len + length_len
            is_truncated = False
            expected_length = length
            
            if value_offset + length > len(data):
                # 数据被截断
                is_truncated = True
                actual_length = len(data) - value_offset
                value = data[value_offset:] if actual_length > 0 else b''
                length = actual_length
            else:
                value = data[value_offset:value_offset + length]
            
            # 获取标签信息
            tag_info = self._get_tag_info(tag, context_hint)
            
            field = TLVField(
                tag=tag,
                tag_bytes=tag_bytes,
                length=length,
                length_bytes=length_bytes,
                value=value,
                offset=absolute_offset,  # 使用绝对偏移量
                level=level,
                tag_name=tag_info[0],
                tag_description=tag_info[1],
                is_truncated=is_truncated,
                expected_length=expected_length
            )
            
            # 解析值
            self._parse_tlv_value(field, context_hint)
            
            # 调试信息
            has_construct_bit = bool(tag_bytes[0] & 0x20)
            # 对于多字节标签，需要计算实际的tag值
            # 0x7F61 = 32609, 0x7F60 = 32608, 0x5F2E = 24366
            is_special_tag = tag in [0x75, 32609, 32608, 0xA1, 24366, 0xBDB, 0x7C]
            
            if level <= 3:  # 只输出前几层的调试信息
                print(f"{'  ' * level}Tag {tag_bytes.hex().upper()} ({tag}) @ 0x{field.offset:04X}, 构造位={has_construct_bit}, 特殊标签={is_special_tag}, 长度={len(value)}")
            
            # 检查是否需要递归解析
            should_recurse = False
            recurse_reason = ""
            
            # 条件1: 有构造位
            if has_construct_bit and not is_truncated:
                should_recurse = True
                recurse_reason = "有构造位"
            # 条件2: 特殊标签
            elif is_special_tag and len(value) > 4 and not is_truncated:
                should_recurse = True
                recurse_reason = "特殊标签"
            # 条件3: 检查内容是否像TLV
            elif len(value) > 2 and not is_truncated:
                # 检查前几个字节是否像有效的TLV标签
                first_byte = value[0]
                if first_byte in [0x02, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x14, 0x16, 0x17, 0x18, 
                                 0x30, 0x31, 0x5F, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
                                 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD]:
                    should_recurse = True
                    recurse_reason = "内容像TLV"
                    
            if should_recurse:
                if level <= 3:
                    print(f"{'  ' * level}→ 尝试递归解析 (原因: {recurse_reason})")
                try:
                    # 传递上下文信息和绝对偏移量
                    child_context = field.tag_name or context_hint
                    field.children = self.analyze_tlv(value, 0, max_depth, level + 1, 
                                                     child_context, value_offset + base_file_offset)
                    if level <= 3:
                        print(f"{'  ' * level}  ✓ 找到 {len(field.children)} 个子节点")
                except Exception as e:
                    if level <= 3:
                        print(f"{'  ' * level}  ✗ 解析失败: {e}")
                    pass
                    
            fields.append(field)
            
            # 处理不定长编码的结束
            if length_bytes == b'\x80':  # 不定长编码
                # 跳过EOC
                eoc_offset = value_offset + length
                if eoc_offset + 2 <= len(data) and data[eoc_offset:eoc_offset+2] == b'\x00\x00':
                    current_offset = eoc_offset + 2
                else:
                    current_offset = value_offset + length
            else:
                current_offset = value_offset + length
            
        return fields
    
    def _get_tag_info(self, tag: int, context: str) -> Tuple[str, str]:
        """根据上下文获取标签信息"""
        # 检查是否在特定上下文中
        if context == "BHT" and tag in self.BHT_TAGS:
            return self.BHT_TAGS[tag]
        
        # 检查护照标签
        if tag in self.PASSPORT_TAGS:
            return self.PASSPORT_TAGS[tag]
            
        # 检查ASN.1标签
        if tag in self.ASN1_TAGS:
            return self.ASN1_TAGS[tag]
            
        # 生成默认名称
        if tag < 0x100:
            return f"Tag_{tag:02X}", f"标签 0x{tag:02X}"
        else:
            return f"Tag_{tag:04X}", f"标签 0x{tag:04X}"
    
    def _parse_tlv_value(self, field: TLVField, context: str):
        """智能解析TLV值"""
        # 根据标签类型解析
        if field.tag == 0x02:  # INTEGER
            field.parsed_value = self._parse_integer(field.value)
            field.value_type = "integer"
            
        elif field.tag == 0x03:  # BIT STRING
            self._parse_bit_string(field)
            
        elif field.tag == 0x06:  # OID
            field.parsed_value = self._decode_oid(field.value)
            field.value_type = "oid"
            
        elif field.tag in [0x0C, 0x13, 0x14, 0x16]:  # 字符串类型
            encoding = 'utf-8' if field.tag == 0x0C else 'ascii'
            try:
                field.parsed_value = field.value.decode(encoding, errors='replace')
                field.value_type = "string"
            except:
                pass
                
        elif field.tag in [0x17, 0x18]:  # 时间类型
            dt = self.parse_datetime(field.value, "asn1")
            if dt:
                field.parsed_value = dt.strftime("%Y-%m-%d %H:%M:%S")
                field.value_type = "datetime"
                
        # 特殊字段解析
        elif field.tag == 0x81 and context in ["BHT", "BIT"]:  # 生物特征类型
            if len(field.value) == 1:
                bio_type = field.value[0]
                field.parsed_value = self.BIOMETRIC_TYPES.get(bio_type, f"未知类型({bio_type})")
                field.value_type = "enum"
                
        elif field.tag == 0x83 and context in ["BHT", "BIT"]:  # 创建日期时间
            dt = self.parse_datetime(field.value, "bcd")
            if dt:
                field.parsed_value = dt.strftime("%Y-%m-%d %H:%M:%S")
                field.value_type = "datetime"
                
        # 检查是否是嵌入的其他格式
        if not field.children and len(field.value) > 4:
            self._detect_embedded_format(field)
            
    def _parse_bit_string(self, field: TLVField):
        """解析BIT STRING（包括嵌套的ASN.1结构）"""
        if len(field.value) < 1:
            field.value_type = "bit_string"
            field.parsed_value = "空位串"
            return
            
        # 第一个字节是未使用的位数
        unused_bits = field.value[0]
        actual_data = field.value[1:] if len(field.value) > 1 else b''
        
        field.value_type = "bit_string"
        field.parsed_value = f"位串 (未使用位: {unused_bits})"
        
        # 检查是否包含嵌套的ASN.1结构（常见于公钥和签名）
        if len(actual_data) > 2 and actual_data[0] in [0x30, 0x31]:  # SEQUENCE或SET
            try:
                # 尝试解析嵌套结构
                nested_fields = self.analyze_tlv(actual_data, 0, 10, field.level + 1, 
                                                "BIT_STRING_CONTENT", field.offset + 1)
                if nested_fields:
                    field.children = nested_fields
                    field.parsed_value = f"位串 (未使用位: {unused_bits}, 包含嵌套结构)"
            except:
                pass
    
    def _parse_integer(self, data: bytes) -> int:
        """解析ASN.1整数"""
        if not data:
            return 0
        # 处理负数
        if data[0] & 0x80:
            # 负数，需要扩展符号位
            return int.from_bytes(data, 'big', signed=True)
        else:
            return int.from_bytes(data, 'big', signed=False)
    
    def _decode_oid(self, data: bytes) -> str:
        """解码OID并映射到可读名称"""
        if not data:
            return ""
            
        # 第一个字节特殊处理
        first = data[0]
        oid_parts = [str(first // 40), str(first % 40)]
        
        # 后续字节
        value = 0
        for byte in data[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                oid_parts.append(str(value))
                value = 0
                
        oid_str = ".".join(oid_parts)
        
        # 查找可读名称
        readable_name = self.OID_MAP.get(oid_str, "")
        if readable_name:
            return f"{oid_str} ({readable_name})"
        return oid_str
    
    def _detect_embedded_format(self, field: TLVField):
        """检测嵌入的数据格式"""
        if len(field.value) < 4:
            return
            
        # 检查JPEG
        if field.value[:3] == b'\xFF\xD8\xFF':
            field.value_type = "embedded_jpeg"
            field.parsed_value = f"JPEG图像 ({len(field.value)} bytes)"
            
        # 检查JP2
        elif field.value[4:8] == b'ftyp' or field.value[:4] == b'\x00\x00\x00\x0C':
            field.value_type = "embedded_jp2"
            field.parsed_value = f"JPEG2000图像 ({len(field.value)} bytes)"
            
        # 检查FAC
        elif field.value[:4] == b'FAC\x00':
            field.value_type = "embedded_fac"
            field.parsed_value = f"FAC格式图像 ({len(field.value)} bytes)"
            # 解析FAC头部
            self._parse_fac_header(field)
    
    def _parse_fac_header(self, field: TLVField):
        """解析FAC头部信息"""
        if len(field.value) < 0x70:
            return
            
        try:
            fac_data = field.value
            # FAC头部结构
            magic = fac_data[0:4]  # 'FAC\x00'
            version = fac_data[4:8]  # '010\x00'
            length = struct.unpack('<I', fac_data[8:12])[0]
            
            # 图像尺寸 (offset 0x62)
            if len(fac_data) >= 0x66:
                width = struct.unpack('>H', fac_data[0x62:0x64])[0]
                height = struct.unpack('>H', fac_data[0x64:0x66])[0]
                
                field.metadata['fac_info'] = {
                    'version': version.decode('ascii', errors='ignore').rstrip('\x00'),
                    'length': length,
                    'width': width,
                    'height': height,
                    'jp2_offset': 0x70
                }
                
                field.parsed_value = f"FAC v{field.metadata['fac_info']['version']} " \
                                   f"{width}x{height} ({length} bytes)"
        except:
            pass
    
    def parse_jp2(self, data: bytes, offset: int = 0) -> List[ParsedField]:
        """解析JPEG2000/JP2格式"""
        fields = []
        current = offset
        
        while current < len(data) - 8:
            # JP2盒子结构: 长度(4) + 类型(4) + 数据
            box_length = struct.unpack('>I', data[current:current+4])[0]
            box_type = data[current+4:current+8]
            
            if box_length == 0:  # 到文件末尾
                box_length = len(data) - current
            elif box_length == 1:  # 64位长度
                if current + 16 > len(data):
                    break
                box_length = struct.unpack('>Q', data[current+8:current+16])[0]
                box_data_start = current + 16
            else:
                box_data_start = current + 8
                
            box_data = data[box_data_start:current + box_length]
            
            # 获取盒子名称
            box_name = self.JP2_BOX_TYPES.get(box_type, box_type.decode('ascii', errors='ignore'))
            
            field = ParsedField(
                name=f"JP2_{box_name}",
                offset=current,
                length=box_length,
                raw_value=data[current:current + box_length],
                type_hint="jp2_box"
            )
            
            # 解析特定盒子
            if box_type == b'ihdr':  # 图像头部
                if len(box_data) >= 14:
                    height = struct.unpack('>I', box_data[0:4])[0]
                    width = struct.unpack('>I', box_data[4:8])[0]
                    components = struct.unpack('>H', box_data[8:10])[0]
                    bpc = box_data[10]
                    field.parsed_value = f"{width}x{height}, {components}分量, {bpc+1}位深度"
                    
            fields.append(field)
            current += box_length
            
            if current >= len(data):
                break
                
        return fields
    
    def parse_x509_certificate(self, data: bytes = None) -> List[ParsedField]:
        """解析X.509证书结构"""
        if data is None:
            data = self.data
            
        fields = []
        
        try:
            # 使用TLV解析器
            tlv_fields = self.analyze_tlv(data, context_hint="X509")
            
            # 转换为更友好的格式
            if tlv_fields and tlv_fields[0].tag == 0x30:  # SEQUENCE
                cert = tlv_fields[0]
                if cert.children:
                    # TBSCertificate
                    tbs = cert.children[0] if cert.children else None
                    if tbs and tbs.children:
                        # 版本
                        version_field = None
                        idx = 0
                        if tbs.children[0].tag == 0xA0:  # 显式版本
                            version_field = tbs.children[0]
                            idx = 1
                            
                        # 序列号
                        if idx < len(tbs.children):
                            serial = tbs.children[idx]
                            if serial.tag == 0x02:
                                fields.append(ParsedField(
                                    name="序列号",
                                    offset=serial.offset,
                                    length=serial.length,
                                    raw_value=serial.value,
                                    parsed_value=serial.value.hex().upper()
                                ))
                                
                        # 继续解析其他字段...
                        # 这里可以添加更多证书字段的解析
                        
        except Exception as e:
            pass
            
        return fields
    
    def parse_pkcs_key(self, data: bytes = None) -> List[ParsedField]:
        """解析PKCS格式的密钥"""
        if data is None:
            data = self.data
            
        fields = []
        
        try:
            # 使用TLV解析器
            tlv_fields = self.analyze_tlv(data, context_hint="PKCS")
            
            if not tlv_fields:
                return fields
                
            # PKCS#8格式
            if self.format == FileFormat.PKCS8:
                # PrivateKeyInfo结构
                if tlv_fields[0].tag == 0x30 and tlv_fields[0].children:
                    # 版本
                    if tlv_fields[0].children[0].tag == 0x02:
                        version = tlv_fields[0].children[0].parsed_value
                        fields.append(ParsedField(
                            name="PKCS#8版本",
                            offset=tlv_fields[0].children[0].offset,
                            length=tlv_fields[0].children[0].length,
                            raw_value=tlv_fields[0].children[0].value,
                            parsed_value=f"v{version}"
                        ))
                        
            # PKCS#1格式
            elif self.format == FileFormat.PKCS1:
                # RSAPrivateKey结构
                if tlv_fields[0].tag == 0x30 and tlv_fields[0].children:
                    key_fields = ["版本", "模数(n)", "公共指数(e)", "私有指数(d)", 
                                 "素数1(p)", "素数2(q)", "指数1", "指数2", "系数"]
                    
                    for i, child in enumerate(tlv_fields[0].children[:9]):
                        if child.tag == 0x02:  # INTEGER
                            field_name = key_fields[i] if i < len(key_fields) else f"字段{i}"
                            value_display = child.parsed_value
                            if i == 1:  # 模数
                                value_display = f"{len(child.value)*8} bits"
                            fields.append(ParsedField(
                                name=field_name,
                                offset=child.offset,
                                length=child.length,
                                raw_value=child.value,
                                parsed_value=value_display
                            ))
                            
        except Exception as e:
            pass
            
        return fields
    
    def calculate_entropy(self) -> float:
        """计算数据熵"""
        if not self.data:
            return 0.0
            
        # 计算字节频率
        byte_counts = Counter(self.data)
        total_bytes = len(self.data)
        
        # 计算香农熵
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def find_patterns(self, pattern: bytes, max_results: int = 100) -> List[int]:
        """查找字节模式"""
        positions = []
        start = 0
        
        while len(positions) < max_results:
            pos = self.data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
            
        return positions
    
    def find_strings(self, min_length: int = 4, encoding: str = 'auto') -> List[Tuple[int, str]]:
        """智能查找字符串"""
        strings = []
        
        # ASCII字符串
        current_string = b''
        start_offset = 0
        
        for i, byte in enumerate(self.data):
            if 32 <= byte < 127:  # 可打印ASCII
                if not current_string:
                    start_offset = i
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    strings.append((start_offset, current_string.decode('ascii')))
                current_string = b''
        
        # 处理最后一个字符串
        if len(current_string) >= min_length:
            strings.append((start_offset, current_string.decode('ascii')))
            
        # UTF-16字符串检测
        if encoding == 'auto' or encoding == 'utf-16':
            # 查找UTF-16 LE模式
            i = 0
            while i < len(self.data) - 1:
                if self.data[i+1] == 0 and 32 <= self.data[i] < 127:
                    # 可能是UTF-16 LE
                    start = i
                    while i < len(self.data) - 1 and self.data[i+1] == 0 and 32 <= self.data[i] < 127:
                        i += 2
                    if i - start >= min_length * 2:
                        try:
                            text = self.data[start:i].decode('utf-16le', errors='ignore')
                            if len(text) >= min_length:
                                strings.append((start, f"[UTF-16LE] {text}"))
                        except:
                            pass
                else:
                    i += 1
                    
        return strings
    
    def extract_embedded_data(self) -> List[Tuple[str, int, bytes]]:
        """提取嵌入的数据（图像、证书等）"""
        embedded = []
        
        # JPEG
        jpeg_positions = self.find_patterns(b'\xFF\xD8\xFF')
        for pos in jpeg_positions:
            # 查找JPEG结束标记
            end_marker = b'\xFF\xD9'
            end_pos = self.data.find(end_marker, pos)
            if end_pos != -1:
                jpeg_data = self.data[pos:end_pos + 2]
                embedded.append(("JPEG", pos, jpeg_data))
                
        # PNG
        png_positions = self.find_patterns(b'\x89PNG\r\n\x1a\n')
        for pos in png_positions:
            # 查找PNG IEND块
            iend = b'IEND\xAE\x42\x60\x82'
            end_pos = self.data.find(iend, pos)
            if end_pos != -1:
                png_data = self.data[pos:end_pos + 8]
                embedded.append(("PNG", pos, png_data))
                
        # 证书（SEQUENCE + OID）
        cert_pattern = b'\x30\x82'  # SEQUENCE with 2-byte length
        cert_positions = self.find_patterns(cert_pattern)
        for pos in cert_positions:
            try:
                if pos + 4 < len(self.data):
                    length = struct.unpack('>H', self.data[pos+2:pos+4])[0]
                    if 100 < length < 10000:  # 合理的证书大小
                        cert_data = self.data[pos:pos+4+length]
                        # 简单验证是否包含证书OID
                        if b'\x55\x04' in cert_data[:200]:  # DN OIDs
                            embedded.append(("X509_CERT", pos, cert_data))
            except:
                pass
                
        return embedded
    
    def hex_dump(self, offset: int = 0, length: int = None, bytes_per_line: int = 16, 
                 show_ascii: bool = True, highlight_ranges: List[Tuple[int, int, str]] = None) -> str:
        """增强的十六进制转储（支持多颜色高亮）"""
        if length is None:
            length = min(512, len(self.data) - offset)
        
        end_offset = min(offset + length, len(self.data))
        output = []
        
        for addr in range(offset, end_offset, bytes_per_line):
            # 地址
            line = f"{Colors.GRAY}{addr:08X}{Colors.RESET}  "
            
            # 十六进制值
            hex_part = ""
            ascii_part = ""
            
            for i in range(bytes_per_line):
                if addr + i < end_offset:
                    byte = self.data[addr + i]
                    
                    # 检查高亮
                    highlight_color = None
                    if highlight_ranges:
                        for start, end, color in highlight_ranges:
                            if start <= addr + i < end:
                                highlight_color = color
                                break
                    
                    if highlight_color:
                        hex_part += f"{highlight_color}{byte:02X}{Colors.RESET} "
                    else:
                        hex_part += f"{byte:02X} "
                    
                    # ASCII部分
                    if 32 <= byte < 127:
                        if highlight_color:
                            ascii_part += f"{highlight_color}{chr(byte)}{Colors.RESET}"
                        else:
                            ascii_part += chr(byte)
                    else:
                        ascii_part += f"{Colors.GRAY}.{Colors.RESET}"
                else:
                    hex_part += "   "
                    ascii_part += " "
                
                # 每8个字节添加额外空格
                if i == 7:
                    hex_part += " "
            
            line += hex_part
            
            if show_ascii:
                line += f" |{ascii_part}|"
            
            output.append(line)
        
        return "\n".join(output)
    
    def generate_detailed_report(self) -> str:
        """生成详细的解析报告"""
        report = []
        
        # 文件基本信息
        report.append(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        report.append(f"{Colors.BOLD}文件解析报告{Colors.RESET}")
        report.append(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        report.append(f"文件路径: {self.filepath}")
        report.append(f"文件大小: {self.filesize:,} 字节 ({self.filesize/1024:.2f} KB)")
        report.append(f"文件格式: {Colors.GREEN}{self.format.value}{Colors.RESET}")
        
        # 哈希值
        report.append(f"\n{Colors.BOLD}[哈希值]{Colors.RESET}")
        report.append(f"MD5:    {hashlib.md5(self.data).hexdigest()}")
        report.append(f"SHA1:   {hashlib.sha1(self.data).hexdigest()}")
        report.append(f"SHA256: {hashlib.sha256(self.data).hexdigest()}")
        
        # 数据特征
        entropy = self.calculate_entropy()
        report.append(f"\n{Colors.BOLD}[数据特征]{Colors.RESET}")
        report.append(f"数据熵: {entropy:.4f} / 8.0")
        if entropy > 7.5:
            report.append(f"  → {Colors.RED}高熵值，可能是加密或压缩数据{Colors.RESET}")
        elif entropy < 3.0:
            report.append(f"  → {Colors.GREEN}低熵值，包含大量重复数据{Colors.RESET}")
        
        # 格式特定解析
        if self.format in [FileFormat.PASSPORT_DG, FileFormat.TLV]:
            report.append(f"\n{Colors.BOLD}[TLV结构解析]{Colors.RESET}")
            try:
                tlv_fields = self.analyze_tlv()
                report.append(self._format_tlv_tree(tlv_fields))
            except Exception as e:
                report.append(f"{Colors.RED}解析错误: {e}{Colors.RESET}")
                
        elif self.format == FileFormat.FAC:
            report.append(f"\n{Colors.BOLD}[FAC格式解析]{Colors.RESET}")
            report.extend(self._parse_fac_format())
            
        elif self.format == FileFormat.X509:
            report.append(f"\n{Colors.BOLD}[X.509证书解析]{Colors.RESET}")
            cert_fields = self.parse_x509_certificate()
            for field in cert_fields:
                report.append(f"{field.name}: {field.get_display_value()}")
                
        elif self.format in [FileFormat.PKCS1, FileFormat.PKCS8]:
            report.append(f"\n{Colors.BOLD}[密钥解析]{Colors.RESET}")
            key_fields = self.parse_pkcs_key()
            for field in key_fields:
                report.append(f"{field.name}: {field.get_display_value()}")
        
        # 查找的字符串
        strings = self.find_strings(min_length=6)
        if strings:
            report.append(f"\n{Colors.BOLD}[发现的字符串] (前20个){Colors.RESET}")
            for offset, string in strings[:20]:
                report.append(f"  0x{offset:04X}: \"{string}\"")
            if len(strings) > 20:
                report.append(f"  ... 还有 {len(strings) - 20} 个字符串")
        
        # 嵌入数据
        embedded = self.extract_embedded_data()
        if embedded:
            report.append(f"\n{Colors.BOLD}[嵌入的数据]{Colors.RESET}")
            for data_type, offset, data in embedded:
                report.append(f"  {data_type} @ 0x{offset:04X} ({len(data):,} bytes)")
        
        return "\n".join(report)
    
    def _format_tlv_tree(self, fields: List[TLVField], indent: str = "") -> str:
        """格式化TLV树形结构"""
        lines = []
        for i, field in enumerate(fields):
            is_last = i == len(fields) - 1
            prefix = "└── " if is_last else "├── "
            
            # 标签信息
            tag_hex = field.tag_bytes.hex().upper()
            value_display = ""
            
            # 显示截断信息
            if field.is_truncated:
                if field.tag_name == "TRUNCATED_TAG":
                    line = f"{indent}{prefix}{Colors.RED}[截断的标签] @ 0x{field.offset:04X}{Colors.RESET}"
                else:
                    line = f"{indent}{prefix}{Colors.CYAN}{tag_hex}{Colors.RESET} " \
                           f"{field.tag_description} {Colors.RED}(截断: {field.length}/{field.expected_length} 字节){Colors.RESET}"
                lines.append(line)
                continue
            
            # 显示解析的值
            if field.parsed_value is not None:
                value_display = f" = {Colors.GREEN}{field.parsed_value}{Colors.RESET}"
            elif field.value_type == "embedded_jpeg":
                value_display = f" = {Colors.BLUE}[JPEG图像]{Colors.RESET}"
            elif field.value_type == "embedded_fac":
                value_display = f" = {Colors.BLUE}[FAC图像]{Colors.RESET}"
            elif len(field.value) <= 16 and not field.children:
                value_hex = field.value.hex().upper()
                value_display = f" = {value_hex}"
            
            # 显示偏移量
            offset_info = f" @ 0x{field.offset:04X}"
            
            line = f"{indent}{prefix}{Colors.CYAN}{tag_hex}{Colors.RESET} " \
                   f"{field.tag_description} ({field.length} bytes){offset_info}{value_display}"
            lines.append(line)
            
            # 递归显示子字段
            if field.children:
                child_indent = indent + ("    " if is_last else "│   ")
                lines.append(self._format_tlv_tree(field.children, child_indent))
                
        return "\n".join(lines)
    
    def _parse_fac_format(self) -> List[str]:
        """解析FAC格式详情"""
        lines = []
        
        if len(self.data) < 0x70:
            lines.append("FAC文件太小，无法解析")
            return lines
            
        try:
            # 基本信息
            magic = self.data[0:4]
            version = self.data[4:8].decode('ascii', errors='ignore').rstrip('\x00')
            length = struct.unpack('<I', self.data[8:12])[0]
            
            lines.append(f"魔术字: {magic.decode('ascii', errors='ignore')}")
            lines.append(f"版本: {version}")
            lines.append(f"数据长度: {length:,} 字节")
            
            # 图像信息
            if len(self.data) >= 0x66:
                width = struct.unpack('>H', self.data[0x62:0x64])[0]
                height = struct.unpack('>H', self.data[0x64:0x66])[0]
                lines.append(f"图像尺寸: {width} x {height}")
                
            # JP2数据
            jp2_start = 0x70
            if len(self.data) > jp2_start + 8:
                lines.append(f"\n嵌入的JP2数据 @ 0x{jp2_start:04X}:")
                jp2_fields = self.parse_jp2(self.data, jp2_start)
                for field in jp2_fields[:5]:  # 显示前5个盒子
                    lines.append(f"  {field.name}: {field.parsed_value or f'{field.length} bytes'}")
                    
        except Exception as e:
            lines.append(f"解析错误: {e}")
            
        return lines
    
    def export_to_code(self, language: str = "c", var_name: str = "data") -> str:
        """导出为编程语言数组"""
        if language == "c":
            # C语言数组
            output = [f"unsigned char {var_name}[] = {{"]
            for i in range(0, len(self.data), 16):
                line = "    "
                for j in range(16):
                    if i + j < len(self.data):
                        line += f"0x{self.data[i+j]:02X}, "
                output.append(line.rstrip(", "))
            output[-1] = output[-1].rstrip(", ")
            output.append("};")
            output.append(f"unsigned int {var_name}_len = {len(self.data)};")
            
        elif language == "python":
            # Python bytes
            output = [f"{var_name} = bytes(["]
            for i in range(0, len(self.data), 16):
                line = "    "
                for j in range(16):
                    if i + j < len(self.data):
                        line += f"0x{self.data[i+j]:02X}, "
                output.append(line.rstrip(", "))
            output[-1] = output[-1].rstrip(", ")
            output.append("])")
            
        elif language == "hex":
            # 纯十六进制
            output = [self.data.hex().upper()]
            
        else:
            output = ["不支持的语言"]
            
        return "\n".join(output)
    
    def interactive_mode(self):
        """增强的交互式分析模式"""
        print(f"{Colors.BOLD}专业十六进制解析器 - 交互模式{Colors.RESET}")
        print(f"文件: {self.filepath} ({self.filesize:,} 字节)")
        print(f"格式: {Colors.GREEN}{self.format.value}{Colors.RESET}")
        print("输入 'help' 查看命令列表\n")
        
        current_offset = 0
        
        while True:
            try:
                cmd = input(f"{Colors.GREEN}hex>{Colors.RESET} ").strip()
                
                if not cmd:
                    continue
                    
                parts = cmd.split()
                command = parts[0].lower()
                
                if command in ['q', 'quit', 'exit']:
                    break
                    
                elif command == 'help':
                    self._show_help()
                    
                elif command in ['h', 'hex']:
                    # hex [offset] [length]
                    offset = int(parts[1], 0) if len(parts) > 1 else current_offset
                    length = int(parts[2], 0) if len(parts) > 2 else 256
                    print(self.hex_dump(offset, length))
                    current_offset = offset + length
                    
                elif command == 'goto':
                    # goto offset
                    if len(parts) > 1:
                        current_offset = int(parts[1], 0)
                        print(f"跳转到 0x{current_offset:04X}")
                    
                elif command == 'find':
                    # find pattern
                    if len(parts) > 1:
                        pattern_str = ' '.join(parts[1:])
                        # 尝试十六进制
                        if all(c in '0123456789abcdefABCDEF ' for c in pattern_str):
                            pattern = bytes.fromhex(pattern_str.replace(' ', ''))
                        else:
                            pattern = pattern_str.encode('utf-8')
                        
                        positions = self.find_patterns(pattern, 20)
                        if positions:
                            print(f"找到 {len(positions)} 个匹配:")
                            for pos in positions:
                                print(f"  0x{pos:04X}")
                                # 显示上下文
                                context_start = max(0, pos - 16)
                                context_end = min(len(self.data), pos + len(pattern) + 16)
                                print(self.hex_dump(context_start, context_end - context_start,
                                    highlight_ranges=[(pos, pos + len(pattern), Colors.BG_YELLOW)]))
                                print()
                        else:
                            print("未找到匹配")
                    
                elif command == 'strings':
                    # strings [min_length]
                    min_len = int(parts[1]) if len(parts) > 1 else 4
                    strings = self.find_strings(min_len)
                    for offset, string in strings[:30]:
                        print(f"0x{offset:04X}: {string}")
                    if len(strings) > 30:
                        print(f"... 还有 {len(strings) - 30} 个字符串")
                    
                elif command == 'tlv':
                    # 解析TLV
                    offset = int(parts[1], 0) if len(parts) > 1 else 0
                    try:
                        fields = self.analyze_tlv(self.data[offset:])
                        print(self._format_tlv_tree(fields))
                    except Exception as e:
                        print(f"TLV解析错误: {e}")
                    
                elif command == 'info':
                    # 显示详细报告
                    print(self.generate_detailed_report())
                    
                elif command == 'extract':
                    # 提取嵌入数据
                    embedded = self.extract_embedded_data()
                    if embedded:
                        print(f"发现 {len(embedded)} 个嵌入数据:")
                        for i, (data_type, offset, data) in enumerate(embedded):
                            print(f"{i+1}. {data_type} @ 0x{offset:04X} ({len(data):,} bytes)")
                        
                        # 询问是否保存
                        choice = input("输入编号保存数据 (或回车跳过): ").strip()
                        if choice.isdigit():
                            idx = int(choice) - 1
                            if 0 <= idx < len(embedded):
                                data_type, offset, data = embedded[idx]
                                filename = f"extracted_{data_type}_{offset:04X}.bin"
                                with open(filename, 'wb') as f:
                                    f.write(data)
                                print(f"已保存到: {filename}")
                    else:
                        print("未发现嵌入数据")
                    
                elif command == 'export':
                    # 导出代码
                    if len(parts) > 1:
                        lang = parts[1]
                        var_name = parts[2] if len(parts) > 2 else "data"
                        print(self.export_to_code(lang, var_name))
                    else:
                        print("用法: export <语言> [变量名]")
                        print("支持的语言: c, python, hex")
                    
                elif command == 'parse':
                    # 智能解析当前位置
                    if self.format == FileFormat.FAC:
                        lines = self._parse_fac_format()
                        for line in lines:
                            print(line)
                    elif self.format in [FileFormat.X509, FileFormat.PKCS1, FileFormat.PKCS8]:
                        fields = self.parse_x509_certificate() if self.format == FileFormat.X509 else self.parse_pkcs_key()
                        for field in fields:
                            print(f"{field.name}: {field.get_display_value()}")
                    else:
                        print("当前格式暂不支持智能解析")
                        
                elif command == 'interpret':
                    # 通用数据解释器
                    if len(parts) >= 3:
                        offset = int(parts[1], 0)
                        length = int(parts[2], 0)
                        self._interpret_data(offset, length)
                    else:
                        print("用法: interpret <offset> <length>")
                        print("将指定字节解释为多种数据类型")
                    
                else:
                    print(f"未知命令: {command}")
                    
            except KeyboardInterrupt:
                print("\n使用 'quit' 退出")
            except Exception as e:
                print(f"错误: {e}")
    
    def _interpret_data(self, offset: int, length: int):
        """通用数据解释器 - 将字节解释为多种数据类型"""
        if offset < 0 or offset + length > len(self.data):
            print(f"{Colors.RED}错误：偏移量或长度超出范围{Colors.RESET}")
            return
            
        data = self.data[offset:offset + length]
        
        print(f"\n{Colors.BOLD}数据解释 @ 0x{offset:04X} ({length} 字节){Colors.RESET}")
        print("=" * 60)
        
        # 原始十六进制
        print(f"{Colors.CYAN}原始数据:{Colors.RESET}")
        print(f"  Hex: {data.hex().upper()}")
        
        # 整数解释
        print(f"\n{Colors.CYAN}整数解释:{Colors.RESET}")
        if length <= 8:
            # 无符号整数
            if length == 1:
                print(f"  uint8:  {data[0]}")
                print(f"  int8:   {struct.unpack('b', data)[0]}")
            elif length == 2:
                print(f"  uint16 BE: {struct.unpack('>H', data)[0]}")
                print(f"  uint16 LE: {struct.unpack('<H', data)[0]}")
                print(f"  int16 BE:  {struct.unpack('>h', data)[0]}")
                print(f"  int16 LE:  {struct.unpack('<h', data)[0]}")
            elif length == 4:
                print(f"  uint32 BE: {struct.unpack('>I', data)[0]}")
                print(f"  uint32 LE: {struct.unpack('<I', data)[0]}")
                print(f"  int32 BE:  {struct.unpack('>i', data)[0]}")
                print(f"  int32 LE:  {struct.unpack('<i', data)[0]}")
            elif length == 8:
                print(f"  uint64 BE: {struct.unpack('>Q', data)[0]}")
                print(f"  uint64 LE: {struct.unpack('<Q', data)[0]}")
                print(f"  int64 BE:  {struct.unpack('>q', data)[0]}")
                print(f"  int64 LE:  {struct.unpack('<q', data)[0]}")
            else:
                # 任意长度
                print(f"  大整数 BE: {int.from_bytes(data, 'big')}")
                print(f"  大整数 LE: {int.from_bytes(data, 'little')}")
        else:
            print(f"  大整数 BE: {int.from_bytes(data, 'big')}")
            print(f"  大整数 LE: {int.from_bytes(data, 'little')}")
        
        # 浮点数解释
        if length == 4:
            print(f"\n{Colors.CYAN}浮点数解释:{Colors.RESET}")
            print(f"  float BE:  {struct.unpack('>f', data)[0]}")
            print(f"  float LE:  {struct.unpack('<f', data)[0]}")
        elif length == 8:
            print(f"\n{Colors.CYAN}浮点数解释:{Colors.RESET}")
            print(f"  double BE: {struct.unpack('>d', data)[0]}")
            print(f"  double LE: {struct.unpack('<d', data)[0]}")
        
        # 时间戳解释
        if length == 4:
            print(f"\n{Colors.CYAN}时间戳解释:{Colors.RESET}")
            ts_be = struct.unpack('>I', data)[0]
            ts_le = struct.unpack('<I', data)[0]
            try:
                print(f"  Unix时间 BE: {ts_be} = {datetime.fromtimestamp(ts_be).strftime('%Y-%m-%d %H:%M:%S')}")
            except:
                print(f"  Unix时间 BE: {ts_be} (超出范围)")
            try:
                print(f"  Unix时间 LE: {ts_le} = {datetime.fromtimestamp(ts_le).strftime('%Y-%m-%d %H:%M:%S')}")
            except:
                print(f"  Unix时间 LE: {ts_le} (超出范围)")
        
        # 字符串解释
        print(f"\n{Colors.CYAN}字符串解释:{Colors.RESET}")
        # ASCII
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        print(f"  ASCII: {ascii_str}")
        
        # UTF-8
        try:
            utf8_str = data.decode('utf-8')
            if utf8_str.isprintable():
                print(f"  UTF-8: {utf8_str}")
        except:
            pass
            
        # UTF-16
        if length >= 2 and length % 2 == 0:
            try:
                utf16le_str = data.decode('utf-16le')
                if utf16le_str.isprintable():
                    print(f"  UTF-16LE: {utf16le_str}")
            except:
                pass
            try:
                utf16be_str = data.decode('utf-16be')
                if utf16be_str.isprintable():
                    print(f"  UTF-16BE: {utf16be_str}")
            except:
                pass
        
        # BCD解释
        if all(b <= 0x99 for b in data):
            bcd_str = self.parse_bcd(data)
            if bcd_str:
                print(f"  BCD: {bcd_str}")
        
        # Base64编码
        print(f"\n{Colors.CYAN}编码形式:{Colors.RESET}")
        print(f"  Base64: {base64.b64encode(data).decode('ascii')}")
        
        # 数据特征
        print(f"\n{Colors.CYAN}数据特征:{Colors.RESET}")
        print(f"  熵: {self._calculate_data_entropy(data):.4f}")
        print(f"  可打印字符: {sum(1 for b in data if 32 <= b < 127)}/{length}")
        print(f"  零字节: {data.count(0)}/{length}")
        
    def _calculate_data_entropy(self, data: bytes) -> float:
        """计算数据块的熵"""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        return entropy
    
    def _show_help(self):
        """显示帮助信息"""
        help_text = f"""
{Colors.BOLD}基础命令:{Colors.RESET}
  h/hex [offset] [length]  - 显示十六进制转储
  goto <offset>            - 跳转到指定偏移
  find <pattern>           - 查找十六进制或字符串（支持高亮）
  strings [min_length]     - 查找字符串（自动检测编码）
  info                     - 显示详细文件报告
  q/quit/exit              - 退出

{Colors.BOLD}解析命令:{Colors.RESET}
  tlv [offset]             - 解析TLV结构（智能识别标签）
  parse                    - 智能解析当前格式
  extract                  - 提取嵌入的数据（图像、证书等）
  interpret <offset> <len> - 通用数据解释器

{Colors.BOLD}导出命令:{Colors.RESET}
  export <语言> [变量名]   - 导出为代码（c/python/hex）

{Colors.BOLD}偏移格式:{Colors.RESET}
  123     - 十进制
  0x7B    - 十六进制
  0173    - 八进制

{Colors.BOLD}查找模式:{Colors.RESET}
  find FF D8 FF            - 十六进制（空格分隔）
  find JPEG                - ASCII字符串
  find 你好                - UTF-8字符串
"""
        print(help_text)


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <文件路径> [命令]")
        print("\n命令:")
        print("  hex [offset] [length]  - 显示十六进制")
        print("  tlv                    - 分析TLV结构")
        print("  info                   - 显示详细报告")
        print("  interactive            - 进入交互模式 (默认)")
        return
    
    filepath = sys.argv[1]
    analyzer = HexAnalyzer(filepath)
    
    if len(sys.argv) > 2:
        command = sys.argv[2].lower()
        
        if command == "hex":
            offset = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
            length = int(sys.argv[4], 0) if len(sys.argv) > 4 else 256
            print(analyzer.hex_dump(offset, length))
            
        elif command == "tlv":
            try:
                fields = analyzer.analyze_tlv()
                print(analyzer._format_tlv_tree(fields))
            except Exception as e:
                print(f"TLV分析错误: {e}")
                
        elif command == "info":
            print(analyzer.generate_detailed_report())
            
        else:
            analyzer.interactive_mode()
    else:
        analyzer.interactive_mode()


if __name__ == "__main__":
    main()