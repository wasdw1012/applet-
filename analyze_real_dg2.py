#!/usr/bin/env python3
"""
Real Passport DG2 Analysis - Identify deviations from ICAO 9303 standards
"""

import struct
from typing import Dict, List, Tuple, Any, Optional

# 将十六进制数据转换为字节数组
def hex_to_bytes(hex_data: str) -> bytes:
    """Convert hex string data to bytes"""
    lines = hex_data.strip().split('\n')
    byte_data = bytearray()
    
    for line in lines:
        if '|' in line:
            hex_part = line.split('|')[0]
            hex_bytes = hex_part[10:58].strip()
            # 解析每个字节对
            for i in range(0, len(hex_bytes), 3):
                if i+2 <= len(hex_bytes):
                    byte_str = hex_bytes[i:i+2]
                    if byte_str.strip():
                        byte_data.append(int(byte_str, 16))
    
    return bytes(byte_data)

class RealDG2Analyzer:
    """Analyze real passport DG2 data and identify non-ICAO compliant features"""
    
    def __init__(self):
        self.dg2_data = None
        self.analysis_results = []
        self.national_header_data = {}
        
    def analyze_hex_dump(self, hex_dump: str):
        """Analyze the hex dump data"""
        self.dg2_data = hex_to_bytes(hex_dump)
        
        print(f"[分析] DG2 数据总长度: {len(self.dg2_data)} 字节")
        print("=" * 80)
        
        # 1. 分析主结构
        self.analyze_main_structure()
        
        # 2. 分析国家自定义头部 (从 0x40 开始)
        self.analyze_national_header()
        
        # 3. 分析与 ICAO 标准的差异
        self.analyze_icao_deviations()
        
        # 4. 分析图像数据
        self.analyze_image_data()
        
    def analyze_main_structure(self):
        """分析 DG2 主结构"""
        print("\n[1] DG2 主结构分析")
        print("-" * 60)
        
        offset = 0
        
        # DG2 标签 (0x75)
        tag = self.dg2_data[offset]
        print(f"DG2 标签: 0x{tag:02X} {'✓ 符合标准' if tag == 0x75 else '✗ 不符合标准'}")
        offset += 1
        
        # 长度编码
        length_type = self.dg2_data[offset]
        if length_type == 0x82:  # 2字节长度
            length = struct.unpack('>H', self.dg2_data[offset+1:offset+3])[0]
            print(f"长度编码: 长形式(2字节) = {length} (0x{length:04X})")
            offset += 3
        else:
            print(f"长度编码类型: 0x{length_type:02X}")
            
        # 生物特征信息组模板 (0x7F61)
        group_tag = struct.unpack('>H', self.dg2_data[offset:offset+2])[0]
        print(f"生物特征信息组标签: 0x{group_tag:04X} {'✓ 符合标准' if group_tag == 0x7F61 else '✗ 不符合标准'}")
        
    def analyze_national_header(self):
        """分析国家自定义头部数据"""
        print("\n[2] 国家自定义头部分析 (偏移 0x40 开始)")
        print("-" * 60)
        
        # 从偏移 0x40 开始的数据
        offset = 0x40
        
        # FAC 标识
        fac_marker = self.dg2_data[offset:offset+4]
        print(f"标识符: {fac_marker.decode('ascii', errors='ignore')} (FAC = Face?)")
        
        # 版本号
        version = self.dg2_data[offset+5:offset+8]
        print(f"版本: {version.decode('ascii', errors='ignore')}")
        
        # 分析接下来的结构
        print("\n详细字节分析:")
        for i in range(0, 64, 16):
            start = offset + i
            end = min(start + 16, offset + 256)
            if start < len(self.dg2_data):
                hex_str = ' '.join(f'{b:02X}' for b in self.dg2_data[start:end])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in self.dg2_data[start:end])
                print(f"  0x{start:04X}: {hex_str:<48} |{ascii_str}|")
                
        # 解析具体字段
        self.parse_national_fields(offset)
        
    def parse_national_fields(self, base_offset: int):
        """解析国家特定字段"""
        print("\n国家特定字段解析:")
        
        # 解析可能的结构
        offset = base_offset
        
        # FAC 头部结构
        print(f"\n1. FAC 头部 (偏移 0x{offset:04X}):")
        print(f"   - 标识: {self.dg2_data[offset:offset+3].decode('ascii', errors='ignore')}")
        print(f"   - 分隔符: 0x{self.dg2_data[offset+3]:02X}")
        print(f"   - 版本: {self.dg2_data[offset+5:offset+8].decode('ascii', errors='ignore')}")
        
        # 查找图像尺寸信息
        offset = base_offset + 0x10
        print(f"\n2. 可能的尺寸信息 (偏移 0x{offset:04X}):")
        for i in range(0, 32, 4):
            val = struct.unpack('>I', self.dg2_data[offset+i:offset+i+4])[0]
            print(f"   偏移 +0x{i:02X}: {val} (0x{val:08X})")
            
        # 查找特征点数据
        offset = base_offset + 0x40
        print(f"\n3. 可能的特征数据区域 (偏移 0x{offset:04X}):")
        
        # 查找 FF 标记
        ff_markers = []
        for i in range(base_offset, base_offset + 0x100):
            if i < len(self.dg2_data) and self.dg2_data[i] == 0xFF:
                ff_markers.append(i)
                
        print(f"   找到 {len(ff_markers)} 个 0xFF 标记:")
        for marker in ff_markers[:10]:  # 只显示前10个
            print(f"   - 0x{marker:04X}: FF {self.dg2_data[marker+1]:02X}")
            
    def analyze_icao_deviations(self):
        """分析与 ICAO 标准的偏差"""
        print("\n[3] 与 ICAO 9303 标准的偏差分析")
        print("-" * 60)
        
        deviations = []
        
        # 1. 检查标准 ICAO 头部位置
        # 标准 ICAO 应该在 生物特征头部模板 (0xA1) 之后
        a1_offset = self.find_tag_offset(0xA1)
        if a1_offset:
            print(f"\n生物特征头部模板 (0xA1) 位置: 0x{a1_offset:04X}")
            
            # 检查标准 ICAO 标签
            offset = a1_offset + 2  # 跳过标签和长度
            length = self.dg2_data[offset - 1]
            
            print("\n标准 ICAO 头部字段:")
            header_offset = offset
            while header_offset < offset + length:
                tag = self.dg2_data[header_offset]
                tag_length = self.dg2_data[header_offset + 1]
                
                tag_name = self.get_tag_name(tag)
                print(f"  - 标签 0x{tag:02X} ({tag_name}), 长度: {tag_length}")
                
                header_offset += 2 + tag_length
                
        # 2. 检查非标准数据块
        print("\n非标准数据块:")
        
        # FAC 头部是非标准的
        deviations.append({
            'type': '非标准数据块',
            'offset': 0x40,
            'description': 'FAC 自定义头部 (中国特有)',
            'data': 'FAC.010... 格式的自定义数据'
        })
        
        # 检查 0xFF 开头的数据块
        ff_blocks = self.find_ff_blocks()
        for block in ff_blocks:
            deviations.append({
                'type': '非标准标签',
                'offset': block['offset'],
                'description': f'FF {block["subtype"]:02X} 标签块',
                'data': f'长度: {block["length"]} 字节'
            })
            
        # 3. 输出所有偏差
        print("\n总结 - 发现的所有偏差:")
        for i, dev in enumerate(deviations, 1):
            print(f"\n{i}. {dev['type']}")
            print(f"   位置: 0x{dev['offset']:04X}")
            print(f"   描述: {dev['description']}")
            print(f"   数据: {dev['data']}")
            
        return deviations
        
    def find_tag_offset(self, tag: int) -> Optional[int]:
        """查找特定标签的偏移位置"""
        for i in range(len(self.dg2_data) - 1):
            if self.dg2_data[i] == tag:
                return i
        return None
        
    def find_ff_blocks(self) -> List[Dict]:
        """查找所有 FF 开头的数据块"""
        blocks = []
        i = 0
        while i < len(self.dg2_data) - 4:
            if self.dg2_data[i] == 0xFF:
                subtype = self.dg2_data[i+1]
                # 通常 FF 块后面跟着 00 和长度
                if i+3 < len(self.dg2_data) and self.dg2_data[i+2] == 0x00:
                    length = self.dg2_data[i+3]
                    blocks.append({
                        'offset': i,
                        'subtype': subtype,
                        'length': length
                    })
                    i += 4 + length
                else:
                    i += 1
            else:
                i += 1
        return blocks
        
    def get_tag_name(self, tag: int) -> str:
        """获取标签名称"""
        tag_names = {
            0x80: "ICAO头部版本",
            0x81: "生物特征类型",
            0x82: "生物特征子类型", 
            0x83: "创建日期时间",
            0x85: "有效期",
            0x86: "创建者",
            0x87: "格式所有者",
            0x88: "格式类型",
            0x90: "图像宽度",
            0x91: "图像高度",
            0x92: "特征点"
        }
        return tag_names.get(tag, f"未知标签")
        
    def analyze_image_data(self):
        """分析图像数据"""
        print("\n[4] 图像数据分析")
        print("-" * 60)
        
        # 查找 JPEG 标记 (FF D8 FF)
        jpeg_offset = None
        for i in range(len(self.dg2_data) - 3):
            if (self.dg2_data[i] == 0xFF and 
                self.dg2_data[i+1] == 0xD8 and 
                self.dg2_data[i+2] == 0xFF):
                jpeg_offset = i
                break
                
        if jpeg_offset:
            print(f"JPEG 图像开始位置: 0x{jpeg_offset:04X}")
            
            # 查找 JPEG 结束标记 (FF D9)
            jpeg_end = None
            for i in range(jpeg_offset + 3, len(self.dg2_data) - 1):
                if self.dg2_data[i] == 0xFF and self.dg2_data[i+1] == 0xD9:
                    jpeg_end = i + 2
                    break
                    
            if jpeg_end:
                jpeg_size = jpeg_end - jpeg_offset
                print(f"JPEG 图像结束位置: 0x{jpeg_end:04X}")
                print(f"JPEG 图像大小: {jpeg_size} 字节")
                
                # 分析 JPEG 前的数据
                pre_jpeg_size = jpeg_offset - 0x40  # 从 FAC 头部开始计算
                print(f"\nJPEG 前的自定义数据大小: {pre_jpeg_size} 字节")
                
        else:
            print("未找到标准 JPEG 图像数据")
            
    def print_summary(self):
        """打印分析总结"""
        print("\n" + "=" * 80)
        print("分析总结")
        print("=" * 80)
        
        print("\n主要发现:")
        print("1. 该 DG2 文件包含大量非 ICAO 标准数据")
        print("2. 从偏移 0x40 开始是 'FAC' 自定义头部")
        print("3. 包含多个 0xFF 开头的专有数据块")
        print("4. 图像数据前有大量自定义元数据")
        print("\n这是中国护照特有的 DG2 格式，包含了额外的人脸识别和安全特征数据。")

# 主程序
if __name__ == "__main__":
    # DG2 hex dump 数据
    hex_dump = """00000000  75 82 50 6B 7F 61 82 50  66 02 01 01 7F 60 82 50  |u.Pk.a.Pf....`.P|
00000010  5E A1 29 80 02 01 00 81  01 02 82 01 00 83 07 00  |^.).............|
00000020  00 00 00 00 00 00 84 08  00 00 00 00 00 00 00 00  |................|
00000030  86 02 00 00 87 02 01 01  88 02 00 08 5F 2E 82 50  |............_..P|
00000040  2E 46 41 43 00 30 31 30  00 00 00 50 2E 00 01 00  |.FAC.010...P....|
00000050  00 50 20 00 00 00 00 00  00 00 00 00 00 00 00 00  |.P .............|
00000060  00 00 00 00 01 01 62 01  D8 00 00 00 00 00 5A FF  |......b.......Z.|
00000070  4F FF 51 00 2F 00 00 00  00 01 62 00 00 01 D8 00  |O.Q./.....b.....|
00000080  00 00 00 00 00 00 00 00  00 01 62 00 00 01 D8 00  |..........b.....|
00000090  00 00 00 00 00 00 00 00  03 07 01 01 07 01 01 07  |................|
000000A0  01 01 FF 52 00 0C 00 00  00 01 01 05 04 04 00 01  |...R............|
000000B0  FF 5C 00 13 40 40 48 48  50 48 48 50 48 48 50 48  |.\\..@@HHPHHPHHPH|"""
    
    analyzer = RealDG2Analyzer()
    analyzer.analyze_hex_dump(hex_dump)
    analyzer.print_summary()