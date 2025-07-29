import os
import sys
import argparse
import struct
import logging
from datetime import datetime, timezone
from PIL import Image, ImageOps
import numpy as np
from io import BytesIO
import hashlib
import traceback

# 检查JPEG2000支持
try:
    import glymur
    HAS_JP2_SUPPORT = True
except ImportError:
    HAS_JP2_SUPPORT = False
    print("警告: 未安装glymur库，JPEG2000支持不可用")

# 检查面部特征点检测支持
try:
    import dlib
    import cv2
    HAS_FACE_DETECTION = True
except ImportError:
    HAS_FACE_DETECTION = False
    print("警告: 未安装dlib或cv2，面部特征点检测不可用")

#模板块标签参数
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
DEFAULT_VALIDITY_YEARS = 10
CREATOR_TAG = 0x86
FORMAT_OWNER_TAG = 0x87  
FORMAT_TYPE_TAG = 0x88  

SAMPLE_NUMBER_TAG = 0x02

CBEFF_PATRON_HEADER_VERSION = 0x0101
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02
BIOMETRIC_SUBTYPE_NO_INFO = 0x00

FORMAT_OWNER_ICAO = 0x0101  
FORMAT_TYPE_FACIAL = 0x0008  #修正：不是5，也可能是5

FACE_IMAGE_TYPE_BASIC = 0x00
FACE_IMAGE_TYPE_FULL_FRONTAL = 0x01  # 新增

IMAGE_TYPE_JPEG = 0x01
IMAGE_TYPE_JPEG2000 = 0x02  #修正：不是2，也可能是2

# 护照尺寸
PASSPORT_PHOTO_SIZES = [
# Minimum size    (240, 320),   
# Small size      (300, 400),   
# Medium size    (360, 480),   
    (420, 560),   # Standard size
# Large size      (480, 640),   
]

#长度
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

#标签和值
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

#辅助函数：7字节日期和8字节有效期
def encode_creation_datetime() -> bytes:

    now = datetime.now(timezone.utc)
    #>HBBBBB = 大端，无符号短整型（年份占2字节），5x 无符号字符型（每个1字节）
    return struct.pack('>HBBBBB', now.year, now.month, now.day, now.hour, now.minute, now.second)

def encode_validity_period(years: int = 10) -> bytes:

    start_dt = datetime.now(timezone.utc)
    end_dt = start_dt.replace(year=start_dt.year + years)
    
    start_bytes = struct.pack('>HBB', start_dt.year, start_dt.month, start_dt.day)
    end_bytes = struct.pack('>HBB', end_dt.year, end_dt.month, end_dt.day)
    
    return start_bytes + end_bytes

# 图像处理
def optimize_image_size(img, target_size=(360, 480)):

    aspect = img.width / img.height
    
    if aspect > target_size[0] / target_size[1]:
        new_width = target_size[0]
        new_height = int(new_width / aspect)
    else:
        new_height = target_size[1]
        new_width = int(new_height * aspect)
    
    return img.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
#预处理提高压缩率
def apply_preprocessing(img):
    img = ImageOps.autocontrast(img, cutoff=2)
    from PIL import ImageFilter
    img = img.filter(ImageFilter.UnsharpMask(radius=0.5, percent=50, threshold=0))
    
    return img

# 面部特征点检测函数
def detect_facial_features(image_path):
    """检测面部特征点并返回ICAO所需的关键点"""
    if not HAS_FACE_DETECTION:
        logging.warning("面部特征点检测不可用，返回默认值")
        return None
    
    try:
        # 读取图像
        img = cv2.imread(image_path)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # 初始化人脸检测器和特征点预测器
        detector = dlib.get_frontal_face_detector()
        # 需要下载 shape_predictor_68_face_landmarks.dat 模型文件
        predictor_path = "shape_predictor_68_face_landmarks.dat"
        if not os.path.exists(predictor_path):
            logging.error(f"未找到dlib模型文件: {predictor_path}")
            return None
            
        predictor = dlib.shape_predictor(predictor_path)
        
        # 检测人脸
        faces = detector(gray)
        if len(faces) == 0:
            logging.warning("未检测到人脸")
            return None
        
        # 使用第一个检测到的人脸
        face = faces[0]
        landmarks = predictor(gray, face)
        
        # 提取68个特征点
        points = []
        for i in range(68):
            point = landmarks.part(i)
            points.append((point.x, point.y))
        
        # 辅助函数：计算点集的中心
        def calculate_center(point_list):
            """计算一组点的中心坐标"""
            x_center = int(sum(p[0] for p in point_list) / len(point_list))
            y_center = int(sum(p[1] for p in point_list) / len(point_list))
            return (x_center, y_center)
        
        # 计算ICAO需要的特征点
        # 左眼中心 (点36-41的中心)
        left_eye_center = calculate_center(points[36:42])
        
        # 右眼中心 (点42-47的中心)
        right_eye_center = calculate_center(points[42:48])
        
        # 鼻尖 (点30)
        nose_tip = points[30]
        
        # 嘴巴中心 (点51和57的中点)
        mouth_center = calculate_center([points[51], points[57]])
        
        # 返回ICAO特征点
        feature_points = [
            {'type': 0x0C, 'x': left_eye_center[0], 'y': left_eye_center[1]},  # 左眼中心
            {'type': 0x0D, 'x': right_eye_center[0], 'y': right_eye_center[1]}, # 右眼中心
            {'type': 0x0E, 'x': nose_tip[0], 'y': nose_tip[1]},                # 鼻尖
            {'type': 0x0F, 'x': mouth_center[0], 'y': mouth_center[1]}         # 嘴巴中心
        ]
        
        logging.info(f"成功检测到{len(feature_points)}个特征点")
        return feature_points
        
    except Exception as e:
        logging.error(f"特征点检测失败: {e}")
        return None

#转换紧凑JPEG2000格式
def convert_image_to_jpeg2000_compact(input_path, target_size, min_size, max_size):
    if not HAS_JP2_SUPPORT:
        raise Exception("JPEG2000 support requires glymur library")
    
    print(f"开始转换: {input_path}")
    print(f"目标大小: {target_size/1000:.1f}KB")
    print(f"大小范围: {min_size/1000:.1f}KB - {max_size/1000:.1f}KB")
    
    img = Image.open(input_path)
    print(f"原始图像: {img.mode} {img.size}")
    
    if img.mode not in ['RGB', 'L']:
        img = img.convert('RGB')
    
    img = apply_preprocessing(img)
    
    best_data = None
    best_info = None
    
    for photo_size in reversed(PASSPORT_PHOTO_SIZES):
        resized_img = optimize_image_size(img, photo_size)
        print(f"尝试尺寸: {resized_img.size}")
        
        uncompressed_size = resized_img.width * resized_img.height * 3
        base_compression_ratio = uncompressed_size / target_size 
        
        for ratio_adjust in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
            temp_path = 'temp_compact.jp2'  # temp_path
            
            # 计算调整后的压缩率
            compression_ratio = base_compression_ratio * ratio_adjust
            
            # 限制压缩率范围
            if compression_ratio > 50:
                compression_ratio = 50
            elif compression_ratio < 10:
                compression_ratio = 10
            
            try:
                # 转换为numpy
                img_array = np.array(resized_img)
                print(f"数组形状: {img_array.shape}, 压缩率: {compression_ratio:.2f}")
                
                # glymur保存，带压缩参数
                glymur.Jp2k(temp_path, data=img_array, cratios=[compression_ratio])
                
                size = os.path.getsize(temp_path)
                print(f"JP2文件大小: {size} bytes ({size/1000:.1f}KB)")
                
                # 检查是否在目标范围
                if min_size <= size <= max_size:  # 使用传入的min_size和max_size
                    with open(temp_path, 'rb') as f:
                        data = f.read()
                    os.remove(temp_path)
                    print(f"找到合适大小: {size} bytes")
                    return data, IMAGE_TYPE_JPEG2000, resized_img.width, resized_img.height
                
                # 保存最好结果
                if size < max_size:
                    with open(temp_path, 'rb') as f:
                        temp_data = f.read()
                    if best_data is None or abs(size - target_size) < abs(len(best_data) - target_size):
                        best_data = temp_data
                        best_info = (resized_img.width, resized_img.height, 
                                   compression_ratio, size)

            except Exception as e:
                print(f"JP2编码错误: {e}")
                import traceback
                traceback.print_exc()
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
    
    if best_data:
        w, h, compression, s = best_info
        print(f"使用最佳匹配: {s} bytes ({s/1000:.1f}KB), {w}x{h}")
        return best_data, IMAGE_TYPE_JPEG2000, w, h
    
    raise Exception(f"无法将图像转换为JPEG2000格式（目标大小: {target_size/1000:.1f}KB）")

def create_facial_record_header():
    header = b''
    header += b'FAC\x00'  # 不是 b'FAC '，必须FAC加NULL字节
    header += b'010\x00'  # 不是 b'0100'，必须010加NULL字节
    header += b'\x00\x00\x00\x00'  # 长度占位符
    header += struct.pack('>H', 1)  # 图像数量
    return header
    
#创建头信息和头信息数据块
def create_facial_information(image_type: int, width: int, height: int, feature_points: list = None) -> bytes:
    
    logging.info("        [5F2E内部] --- 构建大头信息块 (Facial Info) ---")
    
    # 如果没有提供特征点，使用默认值或空列表
    if feature_points is None:
        feature_points = []
    
    feature_points_size = len(feature_points)
    facial_info = b''
    logging.info("        [5F2E内部]     - 特征点数量")
    facial_info += struct.pack('>H', feature_points_size)
    logging.info("        [5F2E内部]     - 性别")
    facial_info += struct.pack('>B', 0x00)  # 性别：未指定
    logging.info("        [5F2E内部]     - 眼睛颜色")
    facial_info += struct.pack('>B', 0x00)  # 眼睛颜色：未指定
    logging.info("        [5F2E内部]     - 头发颜色")
    facial_info += struct.pack('>B', 0x00)  # 头发颜色：未指定
    logging.info("        [5F2E内部]     - 特征掩码")
    facial_info += struct.pack('>BBB', 0, 0, 0)
    logging.info("        [5F2E内部]     - 表情")
    facial_info += struct.pack('>H', 0)
    logging.info("        [5F2E内部]     - 姿态角度")
    facial_info += struct.pack('>BBB', 0, 0, 0)
    logging.info("        [5F2E内部]     - 姿态角度不确定性")
    facial_info += struct.pack('>BBB', 0, 0, 0)
    
    # 添加特征点数据
    if feature_points_size > 0:
        logging.info(f"        [5F2E内部]     - 添加{feature_points_size}个特征点")
        for point in feature_points:
            # 每个特征点：类型(1字节) + X坐标(2字节) + Y坐标(2字节)
            facial_info += struct.pack('>B', point['type'])  # 特征点类型
            facial_info += struct.pack('>H', point['x'])     # X坐标
            facial_info += struct.pack('>H', point['y'])     # Y坐标
            logging.info(f"        [5F2E内部]       - 特征点 0x{point['type']:02X}: ({point['x']}, {point['y']})")

    logging.info("        [5F2E内部] --- 创建大头信息块 (Image Info) ---")
    image_info = b''
    logging.info("        [5F2E内部]     - 大头类型")
    image_info += struct.pack('>B', FACE_IMAGE_TYPE_FULL_FRONTAL) 
    logging.info("        [5F2E内部]     - 大头数据类型")
    image_info += struct.pack('>B', image_type)
    logging.info("        [5F2E内部]     - 宽度 & 高度")
    image_info += struct.pack('>H', width)
    image_info += struct.pack('>H', height)
    logging.info("        [5F2E内部]     - 颜色空间")
    image_info += struct.pack('>B', 0)  # 改为0
    logging.info("        [5F2E内部]     - 来源类型")
    image_info += struct.pack('>B', 0)  # 改为0
    logging.info("        [5F2E内部]     - 设备类型")
    image_info += struct.pack('>H', 0x0000)  # 设备类型是0
    logging.info("        [5F2E内部]     - 质量")
    image_info += struct.pack('>H', 0x0000)  # 质量是0
    
    return facial_info + image_info


# 核心修正创建CBEFF生物特征头部
def create_biometric_header_template() -> bytes:
    logging.info("    [A1内部] -> 创建CBEFF大头子元素")
    
    logging.info("      [A1内部] - [80] Patron Header Version")
    version_tlv = encode_tlv(ICAO_HEADER_VERSION_TAG, b'\x01\x01')
    
    logging.info("      [A1内部] - [81] Biometric Type (Face)")
    bio_type_tlv = encode_tlv(BIOMETRIC_TYPE_TAG, bytes([BIOMETRIC_TYPE_FACIAL_FEATURES]))
    
    logging.info("      [A1内部] - [82] Biometric Subtype")
    bio_subtype_tlv = encode_tlv(BIOMETRIC_SUBTYPE_TAG, bytes([BIOMETRIC_SUBTYPE_NO_INFO]))
    
    logging.info("      [A1内部] - [83] Creation Date & Time")
    creation_tlv = encode_tlv(CREATION_DATE_TIME_TAG, encode_creation_datetime())
    
    logging.info("      [A1内部] - [85] Validity Period")
    validity_tlv = encode_tlv(VALIDITY_PERIOD_TAG, encode_validity_period())
    
    logging.info("      [A1内部] - [86] Creator ID")
    creator_tlv = encode_tlv(CREATOR_TAG, struct.pack('>H', 0x0001))
    
    logging.info("      [A1内部] - [87] Format Owner (ICAO)")
    owner_tlv = encode_tlv(FORMAT_OWNER_TAG, struct.pack('>H', FORMAT_OWNER_ICAO))
    
    logging.info("      [A1内部] - [88] Format Type (Face Image)")
    type_tlv = encode_tlv(FORMAT_TYPE_TAG, struct.pack('>H', FORMAT_TYPE_FACIAL))
    
    header_content = (
        version_tlv + bio_type_tlv + bio_subtype_tlv + creation_tlv + 
        validity_tlv + creator_tlv + owner_tlv + type_tlv
    )
    
    logging.info("    [A1内部] 大头子元素完成")
    return encode_tlv(BIOMETRIC_HEADER_TEMPLATE_TAG, header_content)

#创建数据封装5F2E TLV
def create_biometric_data_block(image_data: bytes, image_type: int, width: int, height: int, feature_points: list = None) -> bytes:
    logging.info("    [5F2E内部] -> 构建ISO19794-5记录")
    
    logging.info("      [5F2E内部] --- 开始构建通用头 (General Header)")
    logging.info("      [5F2E内部]   - 格式标识符FAC")
    info_block = create_facial_information(image_type, width, height, feature_points)
    
    facial_header_prefix = b'FAC\x00' + b'010\x00'  # 修复
    logging.info("      [5F2E内部]   - 版本号 ('0100')")
    
    num_images = struct.pack('>H', 1)
    logging.info("      [5F2E内部]   - 人脸图像数量 (1)")
    
    # 修正：通用头(14字节) + 面部信息块 + 图像数据
    # 通用头：FAC\0(4) + 010\0(4) + 长度(4) + 图像数(2) = 14字节
    total_record_length = 14 + len(info_block) + len(image_data)
    logging.info(f"      [5F2E内部]   - 总记录长度 ({total_record_length} 字节)")
    
    facial_record = (
        facial_header_prefix +
        struct.pack('>I', total_record_length) +
        num_images +
        info_block +
        image_data
    )
    logging.info("    [5F2E内部] ISO19794-5记录完成")
    return encode_tlv(BIOMETRIC_DATA_BLOCK_TAG, facial_record)

# 修复 正确尺寸参数生成DG2
def generate_dg2_compact(image_path, output_path, format_preference, min_size, max_size):
    logging.info(f"生成DG2: {os.path.basename(image_path)} -> {output_path}")
    logging.info(f"目标大小: {min_size/1000:.1f}KB - {max_size/1000:.1f}KB")
    # 强制使用JPEG2000
    if not HAS_JP2_SUPPORT:
        logging.error("JPEG2000是必需的！")
        return False
        
    try:
        target = (min_size + max_size) // 2
        image_data, image_type, width, height = convert_image_to_jpeg2000_compact(
            image_path, target, min_size, max_size)
        format_name = "JPEG2000"
        logging.info(f"  压缩: {len(image_data)/1000:.1f}KB {format_name} ({width}x{height})")
    except Exception as e:
        logging.error(f"JPEG2000转换失败: {e}")
        logging.error("严格验证需要JPEG2000格式")
        return False
        
    # DG2套嵌
    logging.info("[套嵌] 构建DG2 TLV")
    
    # 检测面部特征点
    logging.info("检测面部特征点...")
    feature_points = detect_facial_features(image_path)
    if feature_points:
        logging.info(f"成功检测到 {len(feature_points)} 个特征点")
    else:
        logging.info("未检测到特征点或检测失败，将不包含特征点数据")
    
    # 深入A1内部
    logging.info("  [套嵌] -> 构建 [A1] CBEFF Header...")
    biometric_header_template = create_biometric_header_template()
    logging.info(f"  [套嵌]   - 内部包含8个TLV")
    logging.info(f"  [套嵌] <- [A1] CBEFF Header 完成了 ({len(biometric_header_template)} 字节)")

    # 深入5F2E内部
    logging.info("  [套嵌] -> 开始构建 [5F2E] Biometric Data Block...")
    biometric_data_block = create_biometric_data_block(image_data, image_type, width, height, feature_points)
    logging.info(f"  [套嵌]   - 内部包含ISO 19794-5记录 ")
    logging.info(f"  [套嵌] <- [5F2E] Biometric Data Block 完成了 ({len(biometric_data_block)} 字节)")
    
    # 组合7F60
    biometric_info_template_content = biometric_header_template + biometric_data_block
    biometric_info_template = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, biometric_info_template_content)
    logging.info(f"  [套嵌] -> 组合 [A1] 和 [5F2E] -> [{BIOMETRIC_INFO_TEMPLATE_TAG:X}] Biometric Info Template ({len(biometric_info_template)} 字节)")

    # 组合7F61 
    sample_number = encode_tlv(SAMPLE_NUMBER_TAG, b'\x01')
    biometric_info_group_content = sample_number + biometric_info_template
    biometric_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, biometric_info_group_content)
    logging.info(f"  [套嵌] -> 添加 [02] 组合了 -> [{BIOMETRIC_INFO_GROUP_TEMPLATE_TAG:X}] Biometric Info Group ({len(biometric_info_group)} 字节)")
    
    # 套嵌75
    dg2 = encode_tlv(DG2_TAG, biometric_info_group)
    logging.info(f"[套嵌] -> 最后套嵌 [{DG2_TAG:X}] DG2 Data Object ({len(dg2)} 字节)")
    logging.info("[套嵌] DG2 完成。")
    
    # 保存DG2
    with open(output_path, 'wb') as f:
        f.write(dg2)
    
    # 计算统计
    overhead = len(dg2) - len(image_data)
    checksum = hashlib.sha256(dg2).hexdigest()
    
    print(f" DG2: {len(dg2)/1000:.1f}KB (开销: {overhead}字节)")
    print(f" SHA256: {checksum}")
    
    # DG2
    extract_success, extracted_path, extracted_size = validate_and_extract_dg2_strict(dg2, output_path.replace('.bin', '_extracted'))
    
    if extract_success:
        size_match = abs(extracted_size - len(image_data)) < 100  #允许100字节容错
        print(f" 完整性验证: {'通过' if size_match else '存在差异'}")
    
    # 报告
    info_content = f"""DG2报告
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

# 验证提取函数
def validate_and_extract_dg2_strict(dg2_data: bytes, output_prefix="extracted"):

    print(f"\n解析DG2")

    def parse_ber_length(data, offset):
        length = 0
        len_of_len = 0
        if data[offset] < 0x80:
            length = data[offset]
            len_of_len = 1
        else:
            num_len_bytes = data[offset] & 0x7F
            offset += 1
            if num_len_bytes == 0 or offset + num_len_bytes > len(data):
                raise ValueError("无效的BER长度编码")
            for i in range(num_len_bytes):
                length = (length << 8) | data[offset + i]
            len_of_len = 1 + num_len_bytes
        return length, len_of_len

    try:
        # 1. 解析DG2顶层 (Tag 0x75)
        offset = 0
        if dg2_data[offset] != 0x75:
            raise ValueError(f"DG2顶层Tag不是0x75，而是0x{dg2_data[offset]:02X}")
        offset += 1
        
        len_75, len_bytes_75 = parse_ber_length(dg2_data, offset)
        offset += len_bytes_75
        val_75 = dg2_data[offset : offset + len_75]
        if len(val_75) != len_75: raise ValueError("DG2顶层数据长度不匹配")
        print("  [ ] Tag 0x75 (DG2) ... OK")

        # 2. 解析生物信息组模板 (Tag 0x7F61)
        offset = 0
        if val_75[offset:offset+2] != b'\x7F\x61':
            raise ValueError(f"期望Tag 0x7F61，实际为0x{val_75[offset:offset+2].hex().upper()}")
        offset += 2
        
        len_7F61, len_bytes_7F61 = parse_ber_length(val_75, offset)
        offset += len_bytes_7F61
        val_7F61 = val_75[offset : offset + len_7F61]
        if len(val_7F61) != len_7F61: raise ValueError("Tag 7F61数据长度不匹配")
        print("  Tag 0x7F61 (Biometric Info Group) ... OK")

        # 3. 解析实例数量 (Tag 0x02)
        offset = 0
        if val_7F61[offset] != 0x02:
            raise ValueError(f"期望Tag 0x02，实际为0x{val_7F61[offset]:02X}")
        offset += 1
        if val_7F61[offset] != 0x01: raise ValueError("Tag 0x02长度不为1")
        offset += 1
        if val_7F61[offset] != 0x01: raise ValueError("实例数量不为1")
        offset += 1
        print("  Tag 0x02 (Number of Instances) ... OK")

        # 4. 解析生物信息模板 (Tag 0x7F60)
        if val_7F61[offset:offset+2] != b'\x7F\x60':
            raise ValueError(f"期望Tag 0x7F60，实际为0x{val_7F61[offset:offset+2].hex().upper()}")
        offset += 2
        
        len_7F60, len_bytes_7F60 = parse_ber_length(val_7F61, offset)
        offset += len_bytes_7F60
        val_7F60 = val_7F61[offset : offset + len_7F60]
        if len(val_7F60) != len_7F60: raise ValueError("Tag 7F60数据长度不匹配")
        print("   Tag 0x7F60 (Biometric Info Template) ... OK")

        # 5. 在0x7F60内部，解析CBEFF头 (Tag 0xA1)
        offset = 0
        if val_7F60[offset:offset+2] != b'\x00\xA1' and val_7F60[offset] != 0xA1: # 兼容单字节和双字节A1
             tag_len = 1 if val_7F60[offset] == 0xA1 else 2
             if tag_len==1:
                 offset+=1
             else:
                 offset +=2
        else:
             offset = 2 if val_7F60[offset:offset+2] == b'\x00\xA1' else 1
        
        len_A1, len_bytes_A1 = parse_ber_length(val_7F60, offset)
        offset += len_bytes_A1 + len_A1 # 跳过整个A1 TLV
        print("   Tag 0xA1 (CBEFF Header) ... OK")

        # 6. 继续在0x7F60内部，解析生物数据块 (Tag 0x5F2E)
        if val_7F60[offset:offset+2] != b'\x5F\x2E':
            raise ValueError(f"期望Tag 0x5F2E，实际为0x{val_7F60[offset:offset+2].hex().upper()}")
        offset += 2
        
        len_5F2E, len_bytes_5F2E = parse_ber_length(val_7F60, offset)
        offset += len_bytes_5F2E
        val_5F2E = val_7F60[offset : offset + len_5F2E]
        if len(val_5F2E) != len_5F2E: raise ValueError("Tag 5F2E数据长度不匹配")
        print("   Tag 0x5F2E (Biometric Data Block) ... OK")

        # 7. --- 开始严格解析ISO 19794-5面部记录 ---
        print("  [验证] ISO 19794-5 记录...")
        offset = 0
        
        # 7.1 验证标识符和版本
        if val_5F2E[offset:offset+4] != b'FAC\x00':
            raise ValueError("ISO头标识符不是'FAC\\0'")
        offset += 4
        if val_5F2E[offset:offset+4] != b'010\x00':
            raise ValueError("ISO头版本不是'010\\0'")
        offset += 4
        print("     Format Identifier & Version ... OK")
        
        # 7.2 读取并验证总长度
        record_length = struct.unpack('>I', val_5F2E[offset:offset+4])[0]
        offset += 4
        if record_length != len(val_5F2E):
            raise ValueError(f"ISO记录长度不匹配：声明 {record_length}, 实际 {len(val_5F2E)}")
        print("     Record Length ... OK")
        
        # 7.3 读取图像数量
        num_images = struct.unpack('>H', val_5F2E[offset:offset+2])[0]
        offset += 2
        if num_images != 1: raise ValueError(f"图像数量不为1，而是{num_images}")

        # 7.4 读取并跳过面部信息块和图像信息块
        # (面部信息+特征点+图像信息)
        num_feature_points = struct.unpack('>H', val_5F2E[offset:offset+2])[0]
        offset += 2
        
        facial_info_block_size = 17 # 性别(1)+眼色(1)+发色(1)+特征掩码(3)+表情(2)+姿态(3)+不确定性(3)
        feature_points_block_size = 5 * num_feature_points # 每个特征点5字节：类型(1)+X(2)+Y(2)
        image_info_block_size = 12
        
        # 修正：计算正确的偏移量
        # 头部已经占用了14字节（FAC\0 + 010\0 + 长度 + 图像数）
        # 然后是特征点数量(2字节) + 面部信息(17字节) + 特征点数据 + 图像信息(12字节)
        offset += facial_info_block_size + feature_points_block_size + image_info_block_size
        
        image_data = val_5F2E[offset:]
        
        # 7.5 验证图像数据长度
        expected_image_len = len(val_5F2E) - offset
        if len(image_data) != expected_image_len:
             raise ValueError(f"图像数据长度不匹配：期望 {expected_image_len}, 实际 {len(image_data)}")
        print("   Image Data Offset & Length ... OK")

        # 8. 判断图像类型并保存
        # JP2签名盒包含 "jP  " (0x6A502020) 后跟 CR/LF/0x87/LF
        jp2_signature = b'\x6A\x50\x20\x20\x0D\x0A\x87\x0A'
        
        # 检查前20个字节中是否包含JP2签名
        if jp2_signature in image_data[:20]:
            image_ext = "jp2"
            print("     图像格式: JPEG2000")
            # 找到签名的位置
            sig_pos = image_data[:20].find(jp2_signature)
            print(f"     JP2签名位于偏移: {sig_pos}")
        else:
            # 严格验证只接受JPEG2000
            print("     错误: 图像不是JPEG2000格式")
            if image_data.startswith(b'\xFF\xD8'):
                print("    检测到JPEG格式，但严格验证需要JPEG2000")
                raise ValueError("严格验证要求JPEG2000格式，但检测到JPEG")
            else:
                print(f"    未知的图像文件头: {image_data[:20].hex()}")
                raise ValueError("未知的图像格式，验证失败")

        extracted_path = f"{output_prefix}_strict.{image_ext}"
        with open(extracted_path, 'wb') as f:
            f.write(image_data)
        
        print(f" 提取成功: {extracted_path}")
        print(f" 图像大小: {len(image_data)/1000:.1f}KB ({image_ext.upper()})")
        return True, extracted_path, len(image_data)

    except Exception as e:
        print(f" 验证失败: {e}")
        traceback.print_exc()
        return False, None, 0

def main():
    # 定义配置解决NameError
    SIZE_CONFIGS = {
        'compact': {'min_size': 7000, 'max_size': 9000},
        'normal': {'min_size': 11000, 'max_size': 13000},
        'quality': {'min_size': 20000, 'max_size': 30000},
    }

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    parser = argparse.ArgumentParser(
        description="生成DG2文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python gen_dg2.py dg2.png --size normal     # 标准DG2
        """
    )
    parser.add_argument('image', help='Input image file path')
    parser.add_argument('--format', choices=['auto', 'jpeg', 'jpeg2000'],
                        default='auto', help='Image format preference')
    parser.add_argument('--size', choices=['compact', 'normal', 'quality'],
                        default='compact', help='Size mode')
    parser.add_argument('--out', default='DG2.bin', help='Output file path')
    args = parser.parse_args()

    if not os.path.exists(args.image):
        logging.error(f"文件不存在: {args.image}")
        sys.exit(1)

    logging.info(f"生成DG2 ({args.size}模式) ")
    
    # 从配置中选择参数
    config = SIZE_CONFIGS[args.size]
    
    # 调用改造后的核心函数解决了TypeError
    success = generate_dg2_compact(
        image_path=args.image,
        output_path=args.out,
        format_preference=args.format,
        min_size=config['min_size'],
        max_size=config['max_size']
    )
        
if __name__ == '__main__':
    main()    
    