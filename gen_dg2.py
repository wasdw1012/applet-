#!/usr/bin/env python3
"""
DG2生成器 - 基于ICAO 9303标准的生物特征数据组
严格遵循BIT（生物信息模板）结构
"""

import struct
import sys
from datetime import datetime
from typing import Optional, Tuple

class DG2Generator:
    """DG2生物特征数据组生成器"""
    
    def __init__(self):
        # 标签定义
        self.TAG_DG2 = 0x75
        self.TAG_BIT_GROUP = 0x7F61
        self.TAG_INSTANCE_COUNT = 0x02
        self.TAG_BIT = 0x7F60
        self.TAG_BHT = 0xA1
        self.TAG_ICAO_VERSION = 0x80
        self.TAG_BIOMETRIC_TYPE = 0x81
        self.TAG_BIOMETRIC_SUBTYPE = 0x82
        self.TAG_CREATE_DATETIME = 0x83
        self.TAG_UNKNOWN_84 = 0x84  # 真实护照中的未知字段
        self.TAG_VALIDITY_PERIOD = 0x85
        self.TAG_CREATOR_PID = 0x86
        self.TAG_FORMAT_OWNER = 0x87
        self.TAG_FORMAT_TYPE = 0x88
        self.TAG_BDB = 0x5F2E
        
        # 生物特征类型常量
        self.BIOMETRIC_TYPE_FACE = 0x02
        self.BIOMETRIC_SUBTYPE_FRONTAL = 0x00
        
        # 格式常量
        self.FORMAT_OWNER_ISO = 0x0101
        self.FORMAT_TYPE_JPEG = 0x0001
        self.FORMAT_TYPE_FAC = 0x0008  # FAC格式（真实护照使用）
        
    def encode_length(self, length: int) -> bytes:
        """BER-TLV长度编码"""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        elif length < 65536:
            return bytes([0x82, length >> 8, length & 0xFF])
        else:
            return bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])
    
    def encode_tag(self, tag: int) -> bytes:
        """编码标签（支持单字节和双字节）"""
        if tag <= 0xFF:
            return bytes([tag])
        else:
            return bytes([tag >> 8, tag & 0xFF])
    
    def encode_tlv(self, tag: int, value: bytes) -> bytes:
        """创建TLV结构"""
        tag_bytes = self.encode_tag(tag)
        length_bytes = self.encode_length(len(value))
        return tag_bytes + length_bytes + value
    
    def create_bht(self,
                   icao_version: bytes = None,
                   biometric_type: int = None,
                   biometric_subtype: int = None,
                   create_datetime: datetime = None,
                   validity_period: Tuple[datetime, datetime] = None,
                   creator_pid: int = None,
                   format_owner: int = None,
                   format_type: int = None,
                   use_fac_format: bool = False) -> bytes:
        """创建生物头模板(BHT)"""
        bht_content = b''
        
        # 可选字段
        if icao_version is not None:
            bht_content += self.encode_tlv(self.TAG_ICAO_VERSION, icao_version)
        
        if biometric_type is not None:
            bht_content += self.encode_tlv(self.TAG_BIOMETRIC_TYPE, bytes([biometric_type]))
        
        if biometric_subtype is not None:
            bht_content += self.encode_tlv(self.TAG_BIOMETRIC_SUBTYPE, bytes([biometric_subtype]))
        
        # 创建日期时间字段 (TAG 83)
        if use_fac_format:
            # FAC 真护照模式：必须是 7 字节全 0x00
            bht_content += self.encode_tlv(self.TAG_CREATE_DATETIME, b'\x00' * 7)
        elif create_datetime:
            # 非 FAC 模式，按真实时间编码为 BCD
            dt_str = create_datetime.strftime('%Y%m%d%H%M%S')
            dt_bytes = bytes([int(dt_str[i:i+2], 16) for i in range(0, len(dt_str), 2)])
            bht_content += self.encode_tlv(self.TAG_CREATE_DATETIME, dt_bytes)
        
        if validity_period:
            # 编码有效期（从-到）
            from_dt = validity_period[0].strftime('%Y%m%d')
            to_dt = validity_period[1].strftime('%Y%m%d')
            period_str = from_dt + to_dt
            # BCD编码
            period_bytes = bytes([int(period_str[i:i+2], 16) for i in range(0, len(period_str), 2)])
            bht_content += self.encode_tlv(self.TAG_VALIDITY_PERIOD, period_bytes)
        
        # FAC 模式优先插入未知字段 84，再插入 PID，顺序与真实护照一致
        if use_fac_format:
            bht_content += self.encode_tlv(self.TAG_UNKNOWN_84, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        
        if creator_pid is not None:
            # 大端序编码
            if creator_pid == 0:
                # 按真实护照：长度应为 2 字节 00 00
                pid_bytes = b'\x00\x00'
            else:
                pid_bytes = struct.pack('>I', creator_pid)
                # 去除前导零但保留至少 2 字节
                while len(pid_bytes) > 2 and pid_bytes[0] == 0:
                    pid_bytes = pid_bytes[1:]
            bht_content += self.encode_tlv(self.TAG_CREATOR_PID, pid_bytes)
        
        # 必需字段
        if format_owner is None:
            format_owner = self.FORMAT_OWNER_ISO
        bht_content += self.encode_tlv(self.TAG_FORMAT_OWNER, struct.pack('>H', format_owner))
        
        if format_type is None:
            format_type = self.FORMAT_TYPE_JPEG
        bht_content += self.encode_tlv(self.TAG_FORMAT_TYPE, struct.pack('>H', format_type))
        
        return self.encode_tlv(self.TAG_BHT, bht_content)
    
    def create_bit(self, image_data: bytes, use_fac_format: bool = False, **bht_kwargs) -> bytes:
        """创建单个生物信息模板(BIT)"""
        # 根据格式类型处理图像数据
        if use_fac_format:
            # 使用FAC格式
            processed_data = jpeg_to_fac_format(image_data)
            # 确保BHT中的格式类型正确
            if 'format_type' not in bht_kwargs:
                bht_kwargs['format_type'] = self.FORMAT_TYPE_FAC
        else:
            # 使用标准JPEG格式
            processed_data = image_data
            if 'format_type' not in bht_kwargs:
                bht_kwargs['format_type'] = self.FORMAT_TYPE_JPEG
        
        # 创建生物头模板
        bht_kwargs['use_fac_format'] = use_fac_format
        bht = self.create_bht(**bht_kwargs)
        
        # 创建生物数据块(BDB)
        bdb = self.encode_tlv(self.TAG_BDB, processed_data)
        
        # 组合BHT和BDB
        bit_content = bht + bdb
        
        return self.encode_tlv(self.TAG_BIT, bit_content)
    
    def generate_dg2(self, jpeg_images: list, use_fac_format: bool = False, **kwargs) -> bytes:
        """
        生成完整的DG2数据
        
        参数:
            jpeg_images: JPEG图像数据列表
            use_fac_format: 是否使用FAC格式（真实护照格式）
            kwargs: 传递给BHT的其他参数
        
        返回:
            完整的DG2数据
        """
        if not jpeg_images:
            raise ValueError("At least one JPEG image is required")
        
        if len(jpeg_images) > 9:
            raise ValueError("Maximum 9 biometric instances allowed")
        
        # 生物特征实例计数
        instance_count = self.encode_tlv(self.TAG_INSTANCE_COUNT, bytes([len(jpeg_images)]))
        
        # 生成所有生物信息模板
        bits = b''
        for i, jpeg_data in enumerate(jpeg_images):
            # 为每个图像设置默认参数
            bit_kwargs = kwargs.copy()
            if 'biometric_type' not in bit_kwargs:
                bit_kwargs['biometric_type'] = self.BIOMETRIC_TYPE_FACE
            if 'biometric_subtype' not in bit_kwargs:
                bit_kwargs['biometric_subtype'] = self.BIOMETRIC_SUBTYPE_FRONTAL
            
            bits += self.create_bit(jpeg_data, use_fac_format=use_fac_format, **bit_kwargs)
        
        # 组合成生物信息组模板
        bit_group_content = instance_count + bits
        bit_group = self.encode_tlv(self.TAG_BIT_GROUP, bit_group_content)
        
        # 最终的DG2
        dg2 = self.encode_tlv(self.TAG_DG2, bit_group)
        
        return dg2


def jpeg_to_fac_format(jpeg_data: bytes) -> bytes:
    """将JPEG转换为FAC格式 (按照真实护照规则)"""
    try:
        import io, tempfile, os, struct
        from PIL import Image
        import numpy as np
        import glymur
        
        # ------------- 1. 读取 / 归一化图像 -------------
        img = Image.open(io.BytesIO(jpeg_data))
        # 护照典型尺寸 413×531，但各国固件通常只校验 header 尺寸与 JP2 实际一致
        width, height = img.size
        
        # ------------- 2. 使用 glymur 生成 JP2 数据 -------------
        # glymur 只能写文件，使用 NamedTemporaryFile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jp2') as tmp:
            jp2_path = tmp.name
        try:
            glymur.Jp2k(jp2_path, data=np.asarray(img))
            with open(jp2_path, 'rb') as f:
                jp2_data = f.read()
        finally:
            os.remove(jp2_path)
        
        # ------------- 3. 构造 FAC header -------------
        fac_data = bytearray()
        fac_data.extend(b'FAC\x00')      # 魔术字符串
        fac_data.extend(b'010\x00')      # 版本号 "010\0"
        length_offset = len(fac_data)     # 记录 length 字段位置
        fac_data.extend(b'\x00\x00\x00\x00')  # 4 字节长度 (小端)
        fac_data.extend(b'\x00\x01\x00\x00')  # 未知固定字段
        fac_data.extend(b'\x50\x20\x00\x00')  # 格式/flag
        fac_data.extend(b'\x00' * 16)            # padding
        
        # 图像尺寸信息 (offset 0x60 起)
        fac_data.extend(b'\x00\x00\x00\x00')  # 占位
        fac_data.extend(b'\x01\x01')            # format id
        fac_data.extend(struct.pack('>H', width))
        fac_data.extend(struct.pack('>H', height))
        
        # 固定标记、JP2 magic
        fac_data.extend(b'\x00\x00\x00\x00\x00\x5A')
        fac_data.extend(b'\xFF\x4F\xFF\x51\x00\x2F')
        
        # padding 至 0x70
        while len(fac_data) < 0x70:
            fac_data.append(0x00)
        
        # ------------- 4. 追加 JP2 数据 -------------
        fac_data.extend(jp2_data)
        
        # ------------- 5. 回填 FAC length -------------
        total_length = len(fac_data)            # 真护照写的是 header 后全部字节总长
        struct.pack_into('<I', fac_data, length_offset, total_length)
        
        return bytes(fac_data)
    except Exception as e:
        print(f"警告：无法转换为FAC格式 - {e}")
        return jpeg_data


def compress_jpeg_to_size(image_data: bytes, target_min: int, target_max: int) -> bytes:
    """压缩JPEG到指定大小范围"""
    try:
        from PIL import Image
        import io
    except ImportError:
        print("警告：无法压缩图像，需要PIL库")
        return image_data
    
    # 读取图像
    img = Image.open(io.BytesIO(image_data))
    
    # 二分搜索找到合适的质量
    low_quality = 10
    high_quality = 95
    best_data = image_data
    
    while low_quality <= high_quality:
        mid_quality = (low_quality + high_quality) // 2
        
        # 压缩图像
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=mid_quality, optimize=True)
        compressed = buffer.getvalue()
        
        size = len(compressed)
        
        if target_min <= size <= target_max:
            # 找到合适的大小
            return compressed
        elif size < target_min:
            # 质量太低，需要提高
            low_quality = mid_quality + 1
            if size > len(best_data) and size < target_max:
                best_data = compressed
        else:
            # 质量太高，需要降低
            high_quality = mid_quality - 1
            if target_min <= size <= target_max * 1.1:  # 允许10%的容差
                best_data = compressed
    
    # 如果无法通过调整质量达到目标，尝试调整尺寸
    if len(best_data) > target_max:
        scale = 0.9
        while len(best_data) > target_max and scale > 0.5:
            new_size = (int(img.width * scale), int(img.height * scale))
            resized = img.resize(new_size, Image.Resampling.LANCZOS)
            
            buffer = io.BytesIO()
            resized.save(buffer, format='JPEG', quality=85, optimize=True)
            best_data = buffer.getvalue()
            
            scale -= 0.05
    
    return best_data


def main():
    """示例用法"""
    import os
    
    # 创建生成器
    generator = DG2Generator()
    
    # 获取压缩档位
    if len(sys.argv) > 1:
        try:
            level = int(sys.argv[1])
            if level == 1:
                target_min, target_max = 10000, 12000
                print("使用低档位压缩 (10-12KB)")
            elif level == 3:
                target_min, target_max = 18000, 20000
                print("使用高档位压缩 (18-20KB)")
            else:
                target_min, target_max = 14000, 16000
                print("使用中档位压缩 (14-16KB)")
        except ValueError:
            target_min, target_max = 14000, 16000
            print("使用默认中档位压缩 (14-16KB)")
    else:
        target_min, target_max = 14000, 16000
        print("使用默认中档位压缩 (14-16KB)")
    
    # 检查图像文件是否存在
    image_files = ['dg2.png', 'dg2.jpg', 'dg2.jpeg']
    image_data = None
    used_file = None
    
    for filename in image_files:
        if os.path.exists(filename):
            # 如果是PNG，需要转换为JPEG
            if filename.endswith('.png'):
                try:
                    from PIL import Image
                    import io
                    img = Image.open(filename)
                    # 转换为RGB（如果是RGBA）
                    if img.mode == 'RGBA':
                        rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                        rgb_img.paste(img, mask=img.split()[3])
                        img = rgb_img
                    elif img.mode != 'RGB':
                        img = img.convert('RGB')
                    # 保存为JPEG格式到内存
                    jpeg_buffer = io.BytesIO()
                    img.save(jpeg_buffer, format='JPEG', quality=95)
                    image_data = jpeg_buffer.getvalue()
                except ImportError:
                    print("需要PIL库来转换PNG。请安装: pip install Pillow")
                    return
            else:
                # 直接读取JPEG文件
                with open(filename, 'rb') as f:
                    image_data = f.read()
            used_file = filename
            break
    
    if image_data is None:
        print("未找到图像文件。请提供以下任一文件：")
        print("- dg2.png")
        print("- dg2.jpg") 
        print("- dg2.jpeg")
        return
    
    print(f"使用图像文件: {used_file}")
    print(f"原始图像大小: {len(image_data)} 字节 ({len(image_data)//1024}KB)")
    
    # 压缩图像到目标大小
    compressed_data = compress_jpeg_to_size(image_data, target_min, target_max)
    print(f"压缩后大小: {len(compressed_data)} 字节 ({len(compressed_data)//1024}KB)")
    
    # 强制使用 FAC 真护照模式
    use_fac = True
    print("使用 FAC 真护照模式")

    # 生成DG2，FAC 参数匹配真实护照
    dg2_data = generator.generate_dg2(
        [compressed_data],
        use_fac_format=True,
        icao_version=b'\x01\x00',          # FAC 规定 0100
        biometric_type=0x02,
        biometric_subtype=0x00,
        # create_datetime 省略 → 函数内部写 7B 00
        creator_pid=0,
        format_owner=0x0101
    )
    
    # 保存DG2数据
    with open('dg2.bin', 'wb') as f:
        f.write(dg2_data)
    
    print(f"DG2生成成功，大小: {len(dg2_data)} 字节")
    print(f"已保存到: dg2.bin")
    
    # 显示结构
    print("\nDG2结构:")
    print(f"75 (DG2) [{len(dg2_data)} 字节]")
    print(f"└── 7F61 (BIT Group)")
    print(f"    ├── 02 (Instance Count) = 1")
    print(f"    └── 7F60 (BIT)")
    print(f"        ├── A1 (BHT)")
    print(f"        │   ├── 80 (ICAO Version) = {('0100' if use_fac else '0101')}")
    print(f"        │   ├── 81 (Biometric Type) = 02 (Face)")
    print(f"        │   ├── 82 (Biometric Subtype) = 00 (Frontal)")
    if not use_fac:
        print(f"        │   ├── 83 (Create DateTime)")
        print(f"        │   ├── 86 (Creator PID) = 1234")
    else:
        print(f"        │   ├── 83 (Create DateTime) = 20000101000000")
        print(f"        │   ├── 84 (Unknown Field)")
        print(f"        │   ├── 86 (Creator PID) = 0")
    print(f"        │   ├── 87 (Format Owner) = 0101 (ISO)")
    print(f"        │   └── 88 (Format Type) = {('0008 (FAC)' if use_fac else '0001 (JPEG)')}")
    print(f"        └── 5F2E (BDB) [{len(compressed_data)} 字节 {'FAC' if use_fac else 'JPEG'}]")


if __name__ == "__main__":
    main()
