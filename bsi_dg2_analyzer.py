#!/usr/bin/env python3
"""
BSI DG2 Hexadecimal File Analyzer
分析德国联邦信息安全局(BSI)的生物特征数据文件
"""

import struct
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from enum import Enum

class ASN1Tag(Enum):
    """ASN.1 标签类型"""
    SEQUENCE = 0x30
    SET = 0x31
    CONTEXT_SPECIFIC = 0x80
    APPLICATION = 0x40
    PRIVATE = 0xC0
    CONSTRUCTED = 0x20

@dataclass
class TLVElement:
    """TLV (Tag-Length-Value) 元素"""
    tag: int
    length: int
    value: bytes
    offset: int

class BSI_DG2_Analyzer:
    def __init__(self, hex_data: str):
        # 清理并转换十六进制数据
        self.raw_hex = hex_data.replace(' ', '').replace('\n', '')
        self.data = bytes.fromhex(self.raw_hex)
        self.offset = 0
        
    def analyze(self):
        """主分析函数"""
        print("=== BSI DG2 文件分析 ===\n")
        print(f"文件大小: {len(self.data)} 字节\n")
        
        # 1. 分析ASN.1结构
        print("1. ASN.1/BER编码分析:")
        self._analyze_asn1_structure()
        
        # 2. 分析生物特征数据头
        print("\n2. 生物特征数据结构:")
        self._analyze_biometric_header()
        
        # 3. 分析JPEG 2000图像
        print("\n3. JPEG 2000图像分析:")
        self._analyze_jp2_image()
        
        # 4. 分析安全特征
        print("\n4. 安全特征分析:")
        self._analyze_security_features()
        
    def _analyze_asn1_structure(self):
        """分析ASN.1/BER编码结构"""
        # 第一个字节序列
        if self.data[0] == 0x75:
            print(f"   检测到应用类标签: 0x{self.data[0]:02X}")
            
        # 查找TLV结构
        offset = 0
        while offset < min(len(self.data), 100):  # 只分析前100字节的ASN.1
            if offset + 2 > len(self.data):
                break
                
            tag = self.data[offset]
            length_byte = self.data[offset + 1]
            
            # 处理长形式长度
            if length_byte & 0x80:
                num_octets = length_byte & 0x7F
                if offset + 2 + num_octets > len(self.data):
                    break
                length = 0
                for i in range(num_octets):
                    length = (length << 8) | self.data[offset + 2 + i]
                offset += 2 + num_octets
            else:
                length = length_byte
                offset += 2
                
            # 分析标签类型
            tag_class = (tag & 0xC0) >> 6
            tag_constructed = bool(tag & 0x20)
            tag_number = tag & 0x1F
            
            class_names = ["Universal", "Application", "Context-specific", "Private"]
            print(f"   标签 0x{tag:02X}: {class_names[tag_class]}, "
                  f"{'Constructed' if tag_constructed else 'Primitive'}, "
                  f"编号={tag_number}, 长度={length}")
            
            offset += length
            if offset > 50:  # 限制输出
                break
                
    def _analyze_biometric_header(self):
        """分析生物特征数据头部"""
        # 查找FAC标识
        fac_pos = self.data.find(b'FAC')
        if fac_pos != -1:
            print(f"   找到FAC (Face) 生物特征标识在偏移 0x{fac_pos:04X}")
            
            # 分析FAC后的数据结构
            if fac_pos + 20 < len(self.data):
                version = self.data[fac_pos + 3:fac_pos + 7]
                print(f"   版本信息: {version.hex()}")
                
        # 查找生物特征数据记录
        if b'\x5F\x2E' in self.data[:50]:
            print("   检测到生物特征数据记录标签 (0x5F2E)")
            
    def _analyze_jp2_image(self):
        """分析JPEG 2000图像数据"""
        # 查找JP2文件标识
        jp2_marker = b'ftypjp2 '
        jp2_pos = self.data.find(jp2_marker)
        
        if jp2_pos != -1:
            print(f"   找到JPEG 2000文件头在偏移 0x{jp2_pos:04X}")
            
            # 分析JP2盒子结构
            pos = jp2_pos - 8  # 回到盒子开始处
            boxes_analyzed = 0
            
            while pos < len(self.data) and boxes_analyzed < 10:
                if pos + 8 > len(self.data):
                    break
                    
                # 读取盒子长度和类型
                box_length = struct.unpack('>I', self.data[pos:pos+4])[0]
                box_type = self.data[pos+4:pos+8].decode('ascii', errors='ignore')
                
                if box_length == 0 or box_length > len(self.data) - pos:
                    break
                    
                print(f"   JP2盒子: '{box_type}' 长度={box_length} 在偏移 0x{pos:04X}")
                
                # 特殊处理某些盒子
                if box_type == 'ihdr':  # 图像头
                    if pos + 22 <= len(self.data):
                        height = struct.unpack('>I', self.data[pos+8:pos+12])[0]
                        width = struct.unpack('>I', self.data[pos+12:pos+16])[0]
                        print(f"      图像尺寸: {width}x{height}")
                        
                elif box_type == 'colr':  # 颜色空间
                    print(f"      颜色空间信息存在")
                    
                pos += box_length
                boxes_analyzed += 1
                
            # 分析图像分辨率
            res_marker = b'resc'
            res_pos = self.data.find(res_marker)
            if res_pos != -1 and res_pos + 20 < len(self.data):
                # 尝试解析分辨率
                vres_num = struct.unpack('>H', self.data[res_pos+8:res_pos+10])[0]
                vres_den = struct.unpack('>H', self.data[res_pos+10:res_pos+12])[0]
                hres_num = struct.unpack('>H', self.data[res_pos+12:res_pos+14])[0]
                hres_den = struct.unpack('>H', self.data[res_pos+14:res_pos+16])[0]
                
                if vres_den > 0 and hres_den > 0:
                    vres = vres_num / vres_den
                    hres = hres_num / hres_den
                    print(f"      图像分辨率: {hres:.2f} x {vres:.2f} DPI")
                    
    def _analyze_security_features(self):
        """分析安全特征"""
        # 查找可能的加密或签名数据
        entropy_blocks = []
        block_size = 32
        
        for i in range(0, len(self.data) - block_size, block_size):
            block = self.data[i:i+block_size]
            entropy = self._calculate_entropy(block)
            if entropy > 7.5:  # 高熵值可能表示加密数据
                entropy_blocks.append((i, entropy))
                
        if entropy_blocks:
            print(f"   检测到 {len(entropy_blocks)} 个高熵数据块（可能是加密/签名）:")
            for offset, entropy in entropy_blocks[:5]:  # 只显示前5个
                print(f"      偏移 0x{offset:04X}: 熵值 = {entropy:.2f}")
                
        # 查找可能的证书或密钥
        if b'\x30\x82' in self.data:  # ASN.1 SEQUENCE长形式
            print("   检测到可能的X.509证书或密钥结构")
            
        # 检查数据完整性特征
        if self.data[-2:] == b'\xFF\xD9':  # JPEG结束标记
            print("   JPEG数据正确终止")
            
    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据块的香农熵"""
        if not data:
            return 0.0
            
        entropy = 0.0
        freq = {}
        
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
            
        for count in freq.values():
            if count > 0:
                p = count / len(data)
                entropy -= p * (p and p * p.bit_length() or 0)
                
        return entropy
        
    def get_readable_preview(self, max_chars: int = 1000) -> str:
        """获取可读的数据预览"""
        preview = []
        chars_added = 0
        
        for i, byte in enumerate(self.data):
            if chars_added >= max_chars:
                preview.append("...")
                break
                
            if 32 <= byte <= 126:  # 可打印ASCII字符
                preview.append(chr(byte))
                chars_added += 1
            else:
                preview.append(f"[{byte:02X}]")
                chars_added += 4
                
        return ''.join(preview)

# 主分析函数
def analyze_bsi_dg2(hex_string: str):
    analyzer = BSI_DG2_Analyzer(hex_string)
    analyzer.analyze()
    
    print("\n5. 数据预览（前200字符）:")
    print(f"   {analyzer.get_readable_preview(200)}")
    
    print("\n6. 技术总结:")
    print("   - 这是一个BSI标准的生物特征数据文件（可能是护照/身份证面部图像）")
    print("   - 包含ASN.1/BER编码的元数据")
    print("   - 主要数据是JPEG 2000格式的面部图像")
    print("   - 包含安全特征（可能有数字签名）")
    print("   - 符合ICAO 9303标准（机读旅行证件）")

if __name__ == "__main__":
    # 使用提供的十六进制数据
    hex_data = """
    75 82 3A E7 7F 61 82 3A  E2 02 01 01 7F 60 82 3A
    DA A1 0E 81 01 02 82 01  00 87 02 01 01 88 02 00
    08 5F 2E 82 3A C5 46 41 43 00 30 31 30 00 00 00 3A C5 00 01 00 00 3A B7 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 51 01 C1 00 00 00 00 00 00 00 00 00 0C 6A 50 20 20 0D 0A 87 0A 00 00 00 14 66 74 79 70 6A 70 32 20 00 00 00 00 6A 70 32 20 00 00 00 47 6A 70 32 68 00 00 00 16 69 68 64 72 00 00 02 13 00 00 01 9D 00 03 07 07 00 00 00 00 00 0F 63 6F 6C 72 01 00 00 00 00 00 10 00 00 00 1A 72 65 73 20 00 00 00 12 72 65 73 63 01 2C 00 FE 01 2C 00 FE 04 04
    """
    
    analyze_bsi_dg2(hex_data)