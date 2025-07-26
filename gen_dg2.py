import os
import sys
import argparse
import struct
from datetime import datetime, timezone
from PIL import Image, ImageOps
import numpy as np
from io import BytesIO
import hashlib
import traceback

# Optional: JPEG 2000 support
try:
    import glymur
    HAS_JP2_SUPPORT = True
except ImportError:
    HAS_JP2_SUPPORT = False
    print("Warning: JPEG 2000 support not available (pip install glymur)")


DG2_TAG = 0x75  
BIOMETRIC_INFO_GROUP_TEMPLATE_TAG = 0x7F61  
BIOMETRIC_INFO_TEMPLATE_TAG = 0x7F60  
BIOMETRIC_HEADER_TEMPLATE_TAG = 0xA1  
BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E 

ICAO_HEADER_VERSION_TAG = 0x80
BIOMETRIC_TYPE_TAG = 0x81
BIOMETRIC_SUBTYPE_TAG = 0x82
CREATION_DATE_TIME_TAG = 0x83
VALIDITY_PERIOD_TAG = 0x85
CREATOR_TAG = 0x86
FORMAT_OWNER_TAG = 0x87  
FORMAT_TYPE_TAG = 0x88  


SAMPLE_NUMBER_TAG = 0x02

CBEFF_PATRON_HEADER_VERSION = 0x0101
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02
BIOMETRIC_SUBTYPE_NO_INFO = 0x00

FORMAT_OWNER_ICAO = 0x0101  
FORMAT_TYPE_FACIAL = 0x0005 

# Facial Record Constants
FACE_IMAGE_TYPE_BASIC = 0x00

# Image Type Constants
IMAGE_TYPE_JPEG2000 = 0x00
IMAGE_TYPE_JPEG = 0x01

# Size constraints for compact mode
COMPACT_MIN_SIZE = 7000   
COMPACT_MAX_SIZE = 9000   
COMPACT_TARGET_SIZE = 8000 

# Standard passport photo sizes
PASSPORT_PHOTO_SIZES = [
    (240, 320),   # Minimum size
    (300, 400),   # Small size
    (360, 480),   # Medium size
    (420, 560),   # Standard size
    (480, 640),   # Large size
]


def encode_length(length):

    if length < 0:
        raise ValueError(f"Length cannot be negative: {length}")
    
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return struct.pack('>BH', 0x82, length)  # big-endian
    elif length <= 0xFFFFFF:
        return struct.pack('>BI', 0x83, length)[:-1]  # 3big-endian
    elif length <= 0xFFFFFFFF:
        return struct.pack('>BI', 0x84, length)  # 4big-endian
    else:
        raise ValueError(f"Length too large: {length}")

def encode_tlv(tag, value):

    if not isinstance(tag, int) or tag < 0:
        raise ValueError(f"Invalid tag: {tag}")
    if not isinstance(value, bytes):
        raise TypeError(f"Value must be bytes, got {type(value)}")
    
    if tag > 0xFF:
        tag_bytes = struct.pack('>H', tag)  # big-endian
    else:
        tag_bytes = bytes([tag])
    
    length_bytes = encode_length(len(value))
    
    result = tag_bytes + length_bytes + value
    
    expected_min_size = len(tag_bytes) + 1 + len(value)
    if len(result) < expected_min_size:
        raise ValueError(f"TLV encoding error: result too short")
    
    return result

def encode_datetime(dt):
    """Encode datetime in compact binary format for ICAO compliance"""

    year = dt.year
    return struct.pack('>HBBBBB', 
                      year,      # 修复 年份 2字节大端序！
                      dt.month,  # 月份 (1字节)
                      dt.day,    # 日期 (1字节) 
                      dt.hour,   # 小时 (1字节)
                      dt.minute, # 分钟 (1字节)
                      dt.second) # 秒钟 (1字节)

def encode_validity_period(start_dt, end_dt):
    """Encode validity period in 8-byte format for ICAO compliance"""

    start_packed = struct.pack('>HBB', start_dt.year, start_dt.month, start_dt.day)
    end_packed = struct.pack('>HBB', end_dt.year, end_dt.month, end_dt.day)
    return start_packed + end_packed

# ---------------- Image Processing ----------------

def optimize_image_size(img, target_size=(360, 480)):
    """
    Resize image maintaining aspect ratio
    """
    aspect = img.width / img.height
    
    if aspect > target_size[0] / target_size[1]:
        new_width = target_size[0]
        new_height = int(new_width / aspect)
    else:
        new_height = target_size[1]
        new_width = int(new_height * aspect)
    
    return img.resize((new_width, new_height), Image.Resampling.LANCZOS)

def apply_preprocessing(img):
    """
    Apply preprocessing to improve compression
    """
    img = ImageOps.autocontrast(img, cutoff=2)
    
    from PIL import ImageFilter
    img = img.filter(ImageFilter.UnsharpMask(radius=0.5, percent=50, threshold=0))
    
    return img

def convert_image_to_jpeg_compact(input_path, min_size=COMPACT_MIN_SIZE, max_size=COMPACT_MAX_SIZE):
    """
    Convert image to compact JPEG format
    """
    img = Image.open(input_path)
    
    # 处理透明背景 - 转换为白色背景
    if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
        # 创建白色背景
        background = Image.new('RGB', img.size, (255, 255, 255))
        # 如果是RGBA，直接粘贴
        if img.mode == 'RGBA':
            background.paste(img, mask=img.split()[3])  # 使用alpha通道作为蒙版
        else:
            # 转换后粘贴
            img = img.convert('RGBA')
            background.paste(img, mask=img.split()[3])
        img = background
    elif img.mode not in ['RGB', 'L']:
        img = img.convert('RGB')
    
    img = apply_preprocessing(img)
    
    # JPEG头
    expected_jpeg_header = bytes([0xff,0xd8,0xff,0xe0,0x00,0x10,0x4a,0x46,0x49,0x46])
    
    best_data = None
    best_size_info = None
    
    for photo_size in reversed(PASSPORT_PHOTO_SIZES):
        resized_img = optimize_image_size(img, photo_size)
        
        for quality in range(85, 10, -5):
            buffer = BytesIO()
            resized_img.save(
                buffer, 
                format='JPEG',
                quality=quality,
                optimize=True,
                progressive=False,
                subsampling=2,
            )
            data = buffer.getvalue()
            size = len(data)
            
            # 验JPEG头
            if len(data) >= len(expected_jpeg_header):
                if data[:len(expected_jpeg_header)] != expected_jpeg_header:
                    buffer2 = BytesIO()
                    resized_img.save(
                        buffer2,
                        format='JPEG',
                        quality=quality,
                        optimize=False,
                        progressive=False,
                        subsampling=0,
                    )
                    data2 = buffer2.getvalue()
                    if len(data2) >= len(expected_jpeg_header) and data2[:len(expected_jpeg_header)] == expected_jpeg_header:
                        data = data2
                        size = len(data2)
            
            if min_size <= size <= max_size:
                return data, IMAGE_TYPE_JPEG, resized_img.width, resized_img.height
            
            if size < max_size and (best_data is None or size > len(best_data)):
                if best_data is None or (size > len(best_data) and size < max_size) or (len(best_data) > max_size and size < max_size):
                     best_data = data
                     best_size_info = (resized_img.width, resized_img.height, quality, size)
            elif best_data is None and size > max_size:
                 best_data = data
                 best_size_info = (resized_img.width, resized_img.height, quality, size)

    if best_data:
        w, h, q, s = best_size_info
        return best_data, IMAGE_TYPE_JPEG, w, h
    
    last_resort = optimize_image_size(img, PASSPORT_PHOTO_SIZES[0])
    buffer = BytesIO()
    last_resort.save(buffer, format='JPEG', quality=10, optimize=True, subsampling=2)
    data = buffer.getvalue()
    
    return data, IMAGE_TYPE_JPEG, last_resort.width, last_resort.height

def convert_image_to_jpeg2000_compact(input_path, target_size=COMPACT_TARGET_SIZE):
    """
    Convert image to compact JPEG2000 format
    """
    if not HAS_JP2_SUPPORT:
        raise Exception("JPEG2000 support requires glymur library")
    
    img = Image.open(input_path)
    
    if img.mode not in ['RGB', 'L']:
        img = img.convert('RGB')
    
    img = apply_preprocessing(img)
    
    best_data = None
    best_info = None
    
    for photo_size in reversed(PASSPORT_PHOTO_SIZES):
        resized_img = optimize_image_size(img, photo_size)
        
        uncompressed_size = resized_img.width * resized_img.height * 3
        compression_ratio = uncompressed_size / target_size 
        
        for ratio_adjust in [1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 0.8, 0.6]:
            temp_path = 'temp_compact.jp2'
            
            try:
                jp2 = glymur.Jp2k(temp_path, 'wb')
                jp2[:] = np.array(resized_img)
                current_compression_target = compression_ratio * ratio_adjust
                if current_compression_target <= 0:
                    current_compression_target = 1
                jp2.layer = current_compression_target
                
                size = os.path.getsize(temp_path)
                
                if COMPACT_MIN_SIZE <= size <= COMPACT_MAX_SIZE:
                    with open(temp_path, 'rb') as f:
                        data = f.read()
                    os.remove(temp_path)
                    return data, IMAGE_TYPE_JPEG2000, resized_img.width, resized_img.height
                
                if size < COMPACT_MAX_SIZE:
                    with open(temp_path, 'rb') as f:
                        temp_data = f.read()
                    if best_data is None or size > len(best_data):
                        best_data = temp_data
                        best_info = (resized_img.width, resized_img.height, 
                                   current_compression_target, size)
                elif best_data is None and size > COMPACT_MAX_SIZE:
                    with open(temp_path, 'rb') as f:
                        temp_data = f.read()
                    best_data = temp_data
                    best_info = (resized_img.width, resized_img.height,
                               current_compression_target, size)

            except Exception:
                pass  # 忽略编码错误
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
    
    if best_data:
        w, h, r, s = best_info
        return best_data, IMAGE_TYPE_JPEG2000, w, h
    
    # 回退到JPEG
    return convert_image_to_jpeg_compact(input_path, COMPACT_MIN_SIZE, COMPACT_MAX_SIZE)

# 就他妈是ASCII "0100"就他妈是ASCII "0100"就他妈是ASCII "0100"
# 就他妈是ASCII "0100"就他妈是ASCII "0100"就他妈是ASCII "0100"
# 就他妈是ASCII "0100"就他妈是ASCII "0100"就他妈是ASCII "0100"
def create_facial_record_header():

    header = b''
    header += b'FAC\x00'  # Format Identifier (4 bytes) -
    header += struct.pack('>I', 0x30313030)  # 就他妈是ASCII "0100"就他妈是ASCII "0100"就他妈是ASCII "0100"
    header += b'\x00\x00\x00\x00'  # Length (placeholder, 4 bytes, big-endian)
    header += struct.pack('>H', 1)  # Number of Facial Images (2 bytes, big-endian)
    return header

def create_facial_information(image_data, image_type, width, height):
   
    # 验证尺寸参数
    if width <= 0 or height <= 0:
        raise ValueError(f"Invalid image dimensions: {width}x{height}")
    
    # 字节最大值
    if width > 65535 or height > 65535:
        raise ValueError(f"Image dimensions too large: {width}x{height} (max: 65535x65535)")
    
    facial_info = b''
    
    # Facial Record Data Length (4 bytes)
    feature_points_size = 0  # 特征点数量
    image_info_size = 12     # 实际是12字节，不是14
    facial_record_data_length = 4 + 2 + 1 + 1 + 1 + 3 + 2 + 3 + 3 + (feature_points_size * 8) + image_info_size + len(image_data)
    facial_info += struct.pack('>I', facial_record_data_length)
    
    # Number of Feature Points (2 bytes)
    facial_info += struct.pack('>H', feature_points_size)
    
    # Gender (1 byte) - 0 = 未指定
    facial_info += struct.pack('>B', 0)
    
    # Eye Color (1 byte) - 0 = 未指定
    facial_info += struct.pack('>B', 0)
    
    # Hair Color (1 byte) - 0 = 未指定  
    facial_info += struct.pack('>B', 0)
    
    # Feature Mask (3 bytes) - 全部0
    facial_info += struct.pack('>BBB', 0, 0, 0)
    
    # Expression (2 bytes) - 0 = 中性表情
    facial_info += struct.pack('>H', 0)
    
    # Pose Angle (3 bytes) - 全部0
    facial_info += struct.pack('>BBB', 0, 0, 0)
    
    # Pose Angle Uncertainty (3 bytes) - 全部0
    facial_info += struct.pack('>BBB', 0, 0, 0)
    
    # Face Image Type (1 byte)
    facial_info += struct.pack('>B', FACE_IMAGE_TYPE_BASIC)
    
    # Image Data Type (1 byte)
    facial_info += struct.pack('>B', image_type)
    
    # Image Width (2 bytes, big-endian)
    facial_info += struct.pack('>H', width)
    
    # Image Height (2 bytes, big-endian)
    facial_info += struct.pack('>H', height)
    
    # Image Color Space (1 byte) - 1 = RGB
    facial_info += struct.pack('>B', 1)
    
    # Source Type (1 byte) - 2 = 数字相机
    facial_info += struct.pack('>B', 2)
    
    # Device Type (2 bytes, big-endian) - 0 = 未知
    facial_info += struct.pack('>H', 0)
    
    # Quality (2 bytes, big-endian) - 0 = 未评估
    facial_info += struct.pack('>H', 0)
    
    return facial_info

def create_biometric_header_template():
    
    # ICAO Header Version
    icao_header_version = encode_tlv(ICAO_HEADER_VERSION_TAG, 
                                   struct.pack('>H', CBEFF_PATRON_HEADER_VERSION))
    
    # Biometric Type
    biometric_type = encode_tlv(BIOMETRIC_TYPE_TAG, 
                               bytes([BIOMETRIC_TYPE_FACIAL_FEATURES]))
    
    # Biometric Subtype
    biometric_subtype = encode_tlv(BIOMETRIC_SUBTYPE_TAG, 
                                  bytes([BIOMETRIC_SUBTYPE_NO_INFO]))
    
    # Creation Date/Time
    now = datetime.now(timezone.utc)
    creation_datetime = encode_tlv(CREATION_DATE_TIME_TAG, encode_datetime(now))
    
    # Validity Period 10年
    validity_period = encode_tlv(VALIDITY_PERIOD_TAG, 
                                encode_validity_period(now, now.replace(year=now.year + 10)))
    
    # Creator
    creator = encode_tlv(CREATOR_TAG, struct.pack('>H', 0x0001))
    
    # Format Owner
    format_owner = encode_tlv(FORMAT_OWNER_TAG, 
                             struct.pack('>H', FORMAT_OWNER_ICAO))
    
    # Format Type
    format_type = encode_tlv(FORMAT_TYPE_TAG, 
                            struct.pack('>H', FORMAT_TYPE_FACIAL))
    
    # 组合元素
    header_content = (icao_header_version + biometric_type + biometric_subtype + 
                     creation_datetime + validity_period + creator +
                     format_owner + format_type)
    
    # 生物特征标头
    return encode_tlv(BIOMETRIC_HEADER_TEMPLATE_TAG, header_content)

def validate_dg2_structure(dg2_data, original_image):
    
    if len(dg2_data) < 100:
        raise ValueError("DG2 data too short")
    
    if original_image not in dg2_data:
        raise ValueError("Original image data not found in DG2")
    
    # 验证DG2标签
    expected_tag = bytes([DG2_TAG])
    if not dg2_data.startswith(expected_tag):
        raise ValueError(f"DG2 does not start with correct tag: expected 0x{DG2_TAG:02X}")
    
    # 验证TLV嵌层
    try:
        offset = 1  # 跳过DG2标签
        if dg2_data[offset] & 0x80:  # 长格式长度
            offset += (dg2_data[offset] & 0x7F) + 1
        else:
            offset += 1
        
        # 信息组模板标签 (0x7F61)
        if offset + 1 < len(dg2_data):
            if dg2_data[offset:offset+2] != bytes([0x7F, 0x61]):
                raise ValueError("生物特征信息组模板标签不匹配")
        
    except Exception as e:
        raise ValueError(f"TLV结构验证失败: {e}")

def create_biometric_data_block(image_data, image_type, width, height):
    
    if not isinstance(image_data, bytes) or len(image_data) == 0:
        raise ValueError(f"Invalid image data: {type(image_data)}, length: {len(image_data) if image_data else 0}")
    
    # 记录头部
    facial_header = create_facial_record_header()
    
    # 构建信息
    facial_info = create_facial_information(image_data, image_type, width, height)
    
    # 计算总长度
    total_facial_record_length = len(facial_header) + len(facial_info) + len(image_data)
    
    # 面部记录
    facial_record = (
        facial_header[:8] +                           # FAC\x00 + (8字节)
        struct.pack('>I', total_facial_record_length) + # 总长度 (4字节)
        facial_header[12:] +                          # 图像数量 (2字节)  
        facial_info +                                 # 完整信息
        image_data                                    # 图像数据
    )
    
    # 包装生物特征数据标头
    biometric_data = encode_tlv(BIOMETRIC_DATA_BLOCK_TAG, facial_record)
    
    return biometric_data

def generate_dg2_compact(image_path, output_path='DG2.bin', format_preference='auto', 
                        size_mode='compact'):
    """
    Generate ICAO 9303 compliant DG2 file
    """
    print(f" 生成DG2: {os.path.basename(image_path)} -> {output_path}")
    
    # Set size constraints based on mode
    if size_mode == 'compact':
        min_size, max_size = 6000, 7000
    elif size_mode == 'normal':
        min_size, max_size = 11000, 13000
    else:  # quality
        min_size, max_size = 20000, 30000
    
    print(f" 目标: {min_size/1000:.0f}-{max_size/1000:.0f}KB ({size_mode})")

    try:
        if format_preference == 'jpeg2000' or (format_preference == 'auto' and HAS_JP2_SUPPORT):
            try:
                target = (min_size + max_size) // 2
                image_data, image_type, width, height = convert_image_to_jpeg2000_compact(image_path, target)
                format_name = "JPEG2000"
            except Exception:
                image_data, image_type, width, height = convert_image_to_jpeg_compact(image_path, min_size, max_size)
                format_name = "JPEG"
        else:
            image_data, image_type, width, height = convert_image_to_jpeg_compact(image_path, min_size, max_size)
            format_name = "JPEG"
        
        print(f"  压缩: {len(image_data)/1000:.1f}KB {format_name} ({width}x{height})")
        
    except Exception as e:
        print(f" 图像处理失败: {e}")
        return False
    
    # DG2结构
    biometric_header_template = create_biometric_header_template()
    biometric_data_block = create_biometric_data_block(image_data, image_type, width, height)
    
    biometric_info_template_content = biometric_header_template + biometric_data_block
    biometric_info_template = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, biometric_info_template_content)
    
    sample_number = encode_tlv(SAMPLE_NUMBER_TAG, b'\x01')
    biometric_info_group_content = sample_number + biometric_info_template
    biometric_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, biometric_info_group_content)
    
    dg2 = encode_tlv(DG2_TAG, biometric_info_group)
    
    # 验证结构
    validate_dg2_structure(dg2, image_data)
    
    # 保存DG2
    with open(output_path, 'wb') as f:
        f.write(dg2)
    
    # 计算统计
    overhead = len(dg2) - len(image_data)
    checksum = hashlib.sha256(dg2).hexdigest()[:16]
    
    print(f" DG2: {len(dg2)/1000:.1f}KB (开销: {overhead}字节)")
    print(f" SHA256: {checksum}...")
    
    # DG2提大头看一下
    extract_success, extracted_path, extracted_size = extract_image_from_dg2(dg2, output_path.replace('.bin', '_extracted'))
    
    if extract_success:
        size_match = abs(extracted_size - len(image_data)) < 100  # 允许100字节容错
        print(f" 完整性验证: {'通过' if size_match else '存在差异'}")
    
    # 报告
    info_content = f"""DG2生成报告
生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
源文件: {image_path}
输出: {output_path}
格式: {format_name}
尺寸: {width}x{height}
DG2大小: {len(dg2)} 字节
图像大小: {len(image_data)} 字节
SHA256: {hashlib.sha256(dg2).hexdigest()}
提取验证: {'成功' if extract_success else '失败'}
"""
    
    with open(output_path + ".info", "w", encoding='utf-8') as f:
        f.write(info_content)
    
    print(f" 报告: {output_path}.info")
    return True

def extract_image_from_dg2(dg2_data, output_prefix="extracted"):

    print(f"\n[提取] 从DG2中解析图像...")
    
    try:
        # 解析结构
        if len(dg2_data) < 10:
            raise ValueError("DG2数据太短")
        
        if dg2_data[0] != 0x75:
            raise ValueError(f"不是DG2数据，标签: 0x{dg2_data[0]:02X}")
        
        # 解析长度
        offset = 1
        if dg2_data[offset] & 0x80:
            length_bytes = dg2_data[offset] & 0x7F
            offset += 1 + length_bytes
        else:
            offset += 1
        
        # 查数据块 5F2E
        bio_data_found = False
        while offset < len(dg2_data) - 2:
            if dg2_data[offset] == 0x5F and dg2_data[offset + 1] == 0x2E:
                offset += 2
                bio_data_found = True
                break
            offset += 1
        
        if not bio_data_found:
            raise ValueError("未找到数据块(5F2E)")
        
        # 解析5F2E长度
        bio_length = 0
        if dg2_data[offset] & 0x80:
            length_bytes = dg2_data[offset] & 0x7F
            offset += 1
            for i in range(length_bytes):
                bio_length = (bio_length << 8) | dg2_data[offset + i]
            offset += length_bytes
        else:
            bio_length = dg2_data[offset]
            offset += 1
        
        # 提取生物特征数据
        bio_data = dg2_data[offset:offset + bio_length]
        
        # 查FAC头部
        fac_offset = bio_data.find(b'FAC\x00')
        if fac_offset == -1:
            raise ValueError("未找到FAC头部")
        
        # 跳过FAC头部结构，查找图像数据
        img_offset = fac_offset + 20  # 跳过FAC基本头部
        
        # 查找JPEG头部 FFD8
        jpeg_start = -1
        for i in range(img_offset, len(bio_data) - 1):
            if bio_data[i] == 0xFF and bio_data[i + 1] == 0xD8:
                jpeg_start = i
                break
        
        if jpeg_start == -1:
            # 查找JPEG2000头部
            jp2_start = bio_data.find(b'\xFF\x4F\xFF\x51', img_offset)
            if jp2_start == -1:
                raise ValueError("未找到图像数据")
            
            # JPEG2000格式
            image_data = bio_data[jp2_start:]
            image_ext = "jp2"
        else:
            # JPEG格式 - 查找结束标记FFD9
            jpeg_end = -1
            for i in range(jpeg_start + 2, len(bio_data) - 1):
                if bio_data[i] == 0xFF and bio_data[i + 1] == 0xD9:
                    jpeg_end = i + 2
                    break
            
            if jpeg_end == -1:
                # 如果找不到结束标记，取到数据末尾
                image_data = bio_data[jpeg_start:]
            else:
                image_data = bio_data[jpeg_start:jpeg_end]
            
            image_ext = "jpg"
        
        # 保存提取的图像
        extracted_path = f"{output_prefix}.{image_ext}"
        with open(extracted_path, 'wb') as f:
            f.write(image_data)
        
        print(f"    图像提取成功: {extracted_path}")
        print(f"    图像大小: {len(image_data)/1000:.1f}KB ({image_ext.upper()})")
        
        # 验证提取的图像
        try:
            from PIL import Image
            from io import BytesIO
            img = Image.open(BytesIO(image_data))
            print(f"   ️  图像尺寸: {img.width}x{img.height}")
            return True, extracted_path, len(image_data)
        except Exception as e:
            print(f"     图像验证失败: {e}")
            return True, extracted_path, len(image_data)
            
    except Exception as e:
        print(f"    图像提取失败: {e}")
        return False, None, 0

def main():
    parser = argparse.ArgumentParser(
        description="生成DG2文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""

示例:
    python gen_dg2eco.py photo.jpg                    # 紧凑DG2 (6-7KB左右)
    python gen_dg2eco.py photo.jpg --size normal      # 标准DG2 (12KB左右)  
    python gen_dg2eco.py photo.jpg --format jpeg2000  # 强制JPEG2000格式
        """
    )
    
    parser.add_argument('image', help='Input image file path')
    parser.add_argument('--format', choices=['auto', 'jpeg', 'jpeg2000'], 
                       default='auto', help='Image format preference (default: auto)')
    parser.add_argument('--size', choices=['compact', 'normal', 'quality'],
                       default='compact', help='Size mode (default: compact)')
    parser.add_argument('--out', default='DG2.bin', help='Output file path')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print(f" 文件不存在: {args.image}")
        sys.exit(1)
    
    # Check input file size
    input_size = os.path.getsize(args.image)
    if input_size > 1000000:  # > 1MB
        print(f"  输入图像较大 ({input_size/1000000:.1f}MB)，强压缩")
    
    # Generate DG2
    success = generate_dg2_compact(
        args.image, 
        args.out, 
        args.format,
        args.size
    )
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()