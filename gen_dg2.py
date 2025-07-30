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
import dlib 
import cv2  

# JPEG2000 支持检测
try:
    import glymur
    HAS_JP2_SUPPORT = True
except ImportError:
    HAS_JP2_SUPPORT = False
    print("警告: 未安装 glymur 库，JPEG2000 功能将受限")

# 保留 imagecodecs 作为备选
try:
    import imagecodecs
    HAS_IMAGECODECS = True
except ImportError:
    HAS_IMAGECODECS = False

# 1. 主要结构与模板标签
DG2_TAG = 0x75
BIOMETRIC_INFO_GROUP_TEMPLATE_TAG = 0x7F61
BIOMETRIC_INFO_TEMPLATE_TAG = 0x7F60  # 生物特征信息模板（PyMRTD 期望的层）
BIOMETRIC_HEADER_TEMPLATE_TAG = 0xA1
BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E

# 2. 生物特征头部标签
ICAO_HEADER_VERSION_TAG = 0x80
BIOMETRIC_TYPE_TAG = 0x81
BIOMETRIC_SUBTYPE_TAG = 0x82
CREATION_DATE_TIME_TAG = 0x83
VALIDITY_PERIOD_TAG = 0x85
CREATOR_TAG = 0x86
FORMAT_OWNER_TAG = 0x87
FORMAT_TYPE_TAG = 0x88
IMAGE_WIDTH_TAG = 0x90
IMAGE_HEIGHT_TAG = 0x91
FEATURE_POINTS_TAG = 0x92
SAMPLE_NUMBER_TAG = 0x02

# 3. CBEFF 头部内容常量
CBEFF_PATRON_HEADER_VERSION = 0x0101
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02
BIOMETRIC_SUBTYPE_NO_INFO = 0x00
DEFAULT_VALIDITY_YEARS = 10
FORMAT_OWNER_ICAO = 0x0101
FORMAT_TYPE_FACIAL_JPG = 0x0007
FORMAT_TYPE_FACIAL_JP2 = 0x0008

# 模型文件路径
DLIB_SHAPE_PREDICTOR_PATH = "shape_predictor_68_face_landmarks.dat"

# 4. 程序内部逻辑常量
IMAGE_TYPE_JPEG = 1
IMAGE_TYPE_JPEG2000 = 2

# 5. 图像尺寸常量
PASSPORT_PHOTO_SIZES = [
    (300, 400),
    (360, 480),
    (420, 560),
    (480, 640),
]

# ==============================================================================
# 核心函数
# ==============================================================================

def encode_length(length: int) -> bytes:
    """Encodes an integer length into BER-TLV length octets."""
    if length < 0:
        raise ValueError(f"Length cannot be negative: {length}")
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return bytes([0x82]) + length.to_bytes(2, 'big')
    elif length <= 0xFFFFFF:
        return bytes([0x83]) + length.to_bytes(3, 'big')
    elif length <= 0xFFFFFFFF:
        return bytes([0x84]) + length.to_bytes(4, 'big')
    else:
        raise ValueError(f"Length too large: {length}")

def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encodes a Tag-Length-Value structure."""
    if not isinstance(tag, int) or tag < 0:
        raise ValueError(f"Invalid tag: {tag}")
    if not isinstance(value, bytes):
        raise TypeError(f"Value must be bytes, got {type(value)}")
    
    tag_bytes = tag.to_bytes(2, 'big') if tag > 0xFF else tag.to_bytes(1, 'big')
    length_bytes = encode_length(len(value))
    return tag_bytes + length_bytes + value

def encode_datetime(dt: datetime) -> bytes:
    """Encodes datetime into ICAO compact binary format."""
    return struct.pack('>HBBBBB', dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

def encode_validity_period(start_dt: datetime, end_dt: datetime) -> bytes:
    """Encodes a validity period into ICAO format."""
    start_packed = struct.pack('>HBB', start_dt.year, start_dt.month, start_dt.day)
    end_packed = struct.pack('>HBB', end_dt.year, end_dt.month, end_dt.day)
    return start_packed + end_packed

def optimize_image_size(img: Image.Image, target_size: tuple) -> Image.Image:
    """Resizes an image while maintaining aspect ratio using a high-quality filter."""
    aspect = img.width / img.height
    target_aspect = target_size[0] / target_size[1]
    
    if aspect > target_aspect:
        new_width = target_size[0]
        new_height = int(new_width / aspect)
    else:
        new_height = target_size[1]
        new_width = int(new_height * aspect)
        
    return img.resize((new_width, new_height), Image.Resampling.LANCZOS)

def apply_preprocessing(img: Image.Image) -> Image.Image:
    """Applies pre-processing filters to improve image quality for compression."""
    img = ImageOps.autocontrast(img, cutoff=2)
    from PIL import ImageFilter
    img = img.filter(ImageFilter.UnsharpMask(radius=0.5, percent=50, threshold=0))
    return img

def convert_image_to_jpeg2000_compact(input_path, min_size, max_size):
    """
    符合ICAO 9303标准的JPEG2000压缩实现
    压缩比严格限制在20:1以内
    """
    img = Image.open(input_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    img = apply_preprocessing(img)

    best_data = None
    best_size_info = None
    print("--- 开始JPEG2000压缩 (ICAO合规模式) ---")

    # ICAO合规的压缩比范围：8:1 到 20:1
    # 优先使用推荐范围 10:1 到 15:1
    compression_ratios = [10, 12, 15, 8, 18, 20]  # 最大不超过20:1
    
    # 优先尝试 imagecodecs（如果可用）
    if HAS_IMAGECODECS and False:  # 暂时禁用 imagecodecs，因为 level 参数不是压缩比
        print("使用 imagecodecs 进行JPEG2000压缩...")
        for photo_size in reversed(PASSPORT_PHOTO_SIZES):
            resized_img = optimize_image_size(img, photo_size)
            numpy_img = np.array(resized_img)
            
            for ratio in compression_ratios:
                try:
                    # 使用 imagecodecs 的正确参数
                    encoded = imagecodecs.jpeg2k_encode(
                        numpy_img,
                        level=ratio,         # 使用 level 而不是 rate
                        codecformat='jp2',   # JP2 格式
                        reversible=False     # 有损压缩
                    )
                    size = len(encoded)
                    print(f"    [ICAO合规] 尺寸={photo_size}, level={ratio} -> {size} 字节")

                    if min_size <= size <= max_size:
                        print(f"    ✓ 找到ICAO合规的匹配 (压缩比 {ratio}:1)")
                        return encoded, IMAGE_TYPE_JPEG2000, resized_img.width, resized_img.height

                    if size < max_size and (best_data is None or size > len(best_data)):
                        best_data = encoded
                        best_size_info = (resized_img.width, resized_img.height, ratio, size)
                
                except Exception as e:
                    print(f"    [调试] imagecodecs 压缩失败: {e}")
                    continue
    
    # 如果 imagecodecs 不可用或失败，使用 glymur 作为后备
    if best_data is None and HAS_JP2_SUPPORT:
        print("使用 glymur 作为后备方案...")
        temp_path = 'temp_dg2.jp2'
        
        for photo_size in reversed(PASSPORT_PHOTO_SIZES):
            resized_img = optimize_image_size(img, photo_size)
            numpy_img = np.array(resized_img)
            
            for ratio in compression_ratios:
                try:
                    # 使用glymur保存JPEG2000
                    glymur.Jp2k(temp_path, data=numpy_img, cratios=[ratio])
                    
                    # 读取文件大小
                    size = os.path.getsize(temp_path)
                    print(f"    [ICAO合规] 尺寸={photo_size}, cratios={ratio}:1 -> {size} 字节")

                    if min_size <= size <= max_size:
                        print(f"    ✓ 找到ICAO合规的匹配 (压缩比 {ratio}:1)")
                        with open(temp_path, 'rb') as f:
                            data = f.read()
                        os.remove(temp_path)
                        return data, IMAGE_TYPE_JPEG2000, resized_img.width, resized_img.height
                    
                    # 保存最接近目标的结果
                    with open(temp_path, 'rb') as f:
                        temp_data = f.read()
                    
                    if best_data is None or abs(size - (min_size + max_size) // 2) < abs(len(best_data) - (min_size + max_size) // 2):
                        best_data = temp_data
                        best_size_info = (resized_img.width, resized_img.height, ratio, size)

                except Exception as e:
                    print(f"    [调试] glymur 压缩失败: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
    
    print("--- 压缩循环结束 ---")
    
    if best_data:
        w, h, r, s = best_size_info
        if r <= 20:  # 确保压缩比合规
            print(f"    * 返回ICAO合规结果 ({s} 字节, 压缩比={r}:1)")
        else:
            print(f"    ! 警告: 压缩比 {r}:1 超过ICAO建议的20:1，但仍返回结果 ({s} 字节)")
        
        # 添加大小警告
        if s < min_size:
            print(f"    ! 警告: 文件大小 {s/1000:.1f}KB 小于目标范围 {min_size/1000:.0f}-{max_size/1000:.0f}KB")
        elif s > max_size:
            print(f"    ! 警告: 文件大小 {s/1000:.1f}KB 大于目标范围 {min_size/1000:.0f}-{max_size/1000:.0f}KB")
            
        return best_data, IMAGE_TYPE_JPEG2000, w, h
    
    # 如果都不可用，提示错误
    if not HAS_IMAGECODECS and not HAS_JP2_SUPPORT:
        raise Exception("JPEG2000支持需要 imagecodecs 或 glymur 库，请运行: pip install imagecodecs 或 pip install glymur")
    
    raise Exception("无法完成JPEG2000压缩")

def detect_facial_feature_points(image_np: np.ndarray) -> list:
    """
    [NEW] Detects facial feature points using dlib, focusing on eye centers.
    """
    print("    分析: 正在检测面部特征点...")
    
    # 检查模型文件是否存在
    if not os.path.exists(DLIB_SHAPE_PREDICTOR_PATH):
        print(f"[错误] dlib模型文件未找到: {DLIB_SHAPE_PREDICTOR_PATH}")
        print("       请从 http://dlib.net/files/shape_predictor_68_face_landmarks.dat.bz2 下载并解压。")
        return []

    try:
        detector = dlib.get_frontal_face_detector()
        predictor = dlib.shape_predictor(DLIB_SHAPE_PREDICTOR_PATH)
        
        # dlib处理灰度图效果更好
        gray_image = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)
        
        faces = detector(gray_image, 1)
        
        if not faces:
            print("    分析: ✗ 未在图像中检测到人脸。")
            return []

        # 只处理找到的第一个人脸
        face = faces[0]
        landmarks = predictor(gray_image, face)
        
        # ICAO标准需要瞳孔中心点。dlib的68点模型提供眼眶轮廓点。
        # 我们通过计算眼眶轮廓点的平均坐标来近似瞳孔中心。
        
        # 左眼轮廓点索引: 36-41
        left_eye_points = [(landmarks.part(i).x, landmarks.part(i).y) for i in range(36, 42)]
        left_eye_center_x = sum(p[0] for p in left_eye_points) // 6
        left_eye_center_y = sum(p[1] for p in left_eye_points) // 6

        # 右眼轮廓点索引: 42-47
        right_eye_points = [(landmarks.part(i).x, landmarks.part(i).y) for i in range(42, 48)]
        right_eye_center_x = sum(p[0] for p in right_eye_points) // 6
        right_eye_center_y = sum(p[1] for p in right_eye_points) // 6

        # 根据ISO/IEC 19794-5, 左眼中心类型为3, 右眼中心类型为4
        feature_points = [
            {'type': 0x03, 'x': left_eye_center_x, 'y': left_eye_center_y},
            {'type': 0x04, 'x': right_eye_center_x, 'y': right_eye_center_y}
        ]
        
        print(f"    分析: ✓ 检测到瞳孔中心: 左({left_eye_center_x},{left_eye_center_y}), 右({right_eye_center_x},{right_eye_center_y})")
        return feature_points

    except Exception as e:
        print(f"    分析: ✗ 特征点检测时发生错误: {e}")
        return []

def encode_feature_points_tlv(feature_points: list) -> bytes:
    """
    [NEW] Encodes a list of feature points into a TLV structure (Tag 0x92).
    """
    if not feature_points:
        return b''

    # Value部分 = 特征点数量 (2字节) + 连续的特征点记录
    num_points = len(feature_points)
    value_bytes = num_points.to_bytes(2, 'big')
    
    for point in feature_points:
        # 每个记录 = 类型(1字节) + X坐标(2字节) + Y坐标(2字节)
        point_record = point['type'].to_bytes(1, 'big') + \
                       point['x'].to_bytes(2, 'big') + \
                       point['y'].to_bytes(2, 'big')
        value_bytes += point_record
        
    return encode_tlv(FEATURE_POINTS_TAG, value_bytes)


def create_biometric_header_template(width: int, height: int, image_type: int, feature_points: list = None) -> bytes:
    """
    [v2.1 with Feature Points] Creates the A1 header with all metadata.
    """
    now = datetime.now(timezone.utc)
    validity_end = now.replace(year=now.year + DEFAULT_VALIDITY_YEARS)

    header_items = [
        # ... (此处的其他静态头部项保持不变) ...
        encode_tlv(ICAO_HEADER_VERSION_TAG, struct.pack('>H', CBEFF_PATRON_HEADER_VERSION)),
        encode_tlv(BIOMETRIC_TYPE_TAG, bytes([BIOMETRIC_TYPE_FACIAL_FEATURES])),
        encode_tlv(BIOMETRIC_SUBTYPE_TAG, bytes([BIOMETRIC_SUBTYPE_NO_INFO])),
        encode_tlv(CREATION_DATE_TIME_TAG, encode_datetime(now)),
        encode_tlv(VALIDITY_PERIOD_TAG, encode_validity_period(now, validity_end)),
        encode_tlv(CREATOR_TAG, b'ePassportGen'),
        encode_tlv(FORMAT_OWNER_TAG, struct.pack('>H', FORMAT_OWNER_ICAO)),
    ]
    
    format_type_value = FORMAT_TYPE_FACIAL_JP2 if image_type == IMAGE_TYPE_JPEG2000 else FORMAT_TYPE_FACIAL_JPG
    header_items.append(encode_tlv(FORMAT_TYPE_TAG, struct.pack('>H', format_type_value)))

    header_items.append(encode_tlv(IMAGE_WIDTH_TAG, width.to_bytes(2, 'big')))
    header_items.append(encode_tlv(IMAGE_HEIGHT_TAG, height.to_bytes(2, 'big')))

    # 【核心修改】如果传入了特征点，就编码并添加
    if feature_points:
        header_items.append(encode_feature_points_tlv(feature_points))

    header_content = b''.join(header_items)
    return encode_tlv(BIOMETRIC_HEADER_TEMPLATE_TAG, header_content)

def create_biometric_data_block(image_data: bytes) -> bytes:
    """[v2.0] Wraps the raw image data into a Biometric Data Block (5F2E)."""
    if not isinstance(image_data, bytes) or not image_data:
        raise ValueError("Invalid image data provided to create_biometric_data_block.")
    return encode_tlv(BIOMETRIC_DATA_BLOCK_TAG, image_data)

def validate_and_extract_dg2_strict(dg2_data: bytes, output_prefix="extracted") -> tuple[bool, str, int]:
    """
    [NEW] Validates the strict, compliant DG2 structure and extracts the image.
    Structure: 75 -> 7F61 -> (02 + 7F60 -> (A1 + 5F2E))
    """
    print("    验证: 正在使用严格模式验证DG2结构...")
    try:
        # A simple TLV parser
        def parse_tlv(data):
            offset = 0
            tlv_map = {}
            while offset < len(data):
                tag = data[offset]
                if tag & 0x1F == 0x1F: # Multi-byte tag
                    tag = (tag << 8) | data[offset+1]
                    offset += 2
                else:
                    offset += 1
                
                length = data[offset]
                offset += 1
                if length & 0x80:
                    len_bytes = length & 0x7F
                    length = int.from_bytes(data[offset:offset+len_bytes], 'big')
                    offset += len_bytes
                
                value = data[offset:offset+length]
                tlv_map[tag] = value
                offset += length
            return tlv_map

        # 1. Parse DG2 (Tag 75)
        if dg2_data[0] != DG2_TAG: raise ValueError("DG2 does not start with 0x75")
        dg2_content = parse_tlv(dg2_data)[DG2_TAG]

        # 2. Parse Biometric Info Group (Tag 7F61)
        if not dg2_content.startswith(b'\x7F\x61'): raise ValueError("0x75 does not contain 0x7F61")
        group_content = parse_tlv(dg2_content)[BIOMETRIC_INFO_GROUP_TEMPLATE_TAG]
        
        # 3. Parse content of 7F61
        parsed_group = parse_tlv(group_content)
        
        # Check for biometric info template (7F60)
        if BIOMETRIC_INFO_TEMPLATE_TAG in parsed_group:
            # New structure with 7F60 layer
            biometric_info = parse_tlv(parsed_group[BIOMETRIC_INFO_TEMPLATE_TAG])
            if BIOMETRIC_DATA_BLOCK_TAG not in biometric_info:
                raise ValueError("0x7F60 does not contain Biometric Data Block (0x5F2E)")
            image_data = biometric_info[BIOMETRIC_DATA_BLOCK_TAG]
        elif BIOMETRIC_DATA_BLOCK_TAG in parsed_group:
            # Old structure without 7F60 layer (for backward compatibility)
            image_data = parsed_group[BIOMETRIC_DATA_BLOCK_TAG]
        else:
            raise ValueError("Cannot find Biometric Data Block (0x5F2E)")
        
        # 4. Save and verify extracted image
        image_ext = "jp2"
        extracted_path = f"{output_prefix}.{image_ext}"
        with open(extracted_path, 'wb') as f:
            f.write(image_data)
        
        img = Image.open(BytesIO(image_data))
        print(f"    验证: ✓ 结构合规，成功提取图像 ({img.width}x{img.height}) -> {extracted_path}")
        return True, extracted_path, len(image_data)

    except Exception as e:
        print(f"    验证: ✗ DG2结构验证失败: {e}")
        return False, None, 0

def generate_dg2_compact(image_path, output_path='DG2.bin', size_mode='compact'):
    """
    [v2.0 Final] Generates a fully ICAO 9303 compliant DG2 file.
    """
    print(f"--> 生成DG2: {os.path.basename(image_path)} -> {output_path}")

    if size_mode == 'compact':
        min_size, max_size = 10000, 15000
    elif size_mode == 'normal':
        min_size, max_size = 15000, 20000
    else: # quality
        min_size, max_size = 20000, 30000
    print(f"    目标: {min_size/1000:.0f}-{max_size/1000:.0f}KB ({size_mode})")

    try:
        print("    压缩: 正在生成 JPEG2000 图像...")
        image_data, image_type, width, height = convert_image_to_jpeg2000_compact(
            image_path, min_size, max_size
        )
        format_name = "JPEG2000"
        print(f"    压缩: ✓ {len(image_data)/1000:.1f}KB {format_name} ({width}x{height})")
        
        # 【新增调用】在得到图像数据后，立即进行特征点检测
        # 我们需要一个未压缩的numpy数组来进行检测
        pil_image = Image.open(BytesIO(image_data))
        numpy_image_for_detection = np.array(pil_image)
        feature_points = detect_facial_feature_points(numpy_image_for_detection)

    except Exception as e:
        print(f"[错误] 图像处理失败: {e}")
        traceback.print_exc()
        return False

    print("    组装: 正在构建合规的DG2结构...")
    # 【修改调用】将 feature_points 传递给header创建函数
    biometric_header = create_biometric_header_template(width, height, image_type, feature_points)
    biometric_data = create_biometric_data_block(image_data)
    
    # 构建生物特征信息模板 (7F60) - PyMRTD 期望的结构
    biometric_info_content = biometric_header + biometric_data
    biometric_info_template = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, biometric_info_content)
    
    # 生物特征实例数量
    sample_number = encode_tlv(SAMPLE_NUMBER_TAG, b'\x01')
    
    # 构建生物特征信息组模板 (7F61)
    biometric_info_group_content = sample_number + biometric_info_template
    biometric_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, biometric_info_group_content)
    
    # 最终的 DG2 结构
    dg2 = encode_tlv(DG2_TAG, biometric_info_group)
    print("    组装: ✓ DG2结构构建完成")

    with open(output_path, 'wb') as f:
        f.write(dg2)
    
    overhead = len(dg2) - len(image_data)
    checksum = hashlib.sha256(dg2).hexdigest()
    
    print(f"--> DG2生成成功: {len(dg2)/1000:.1f}KB (数据开销: {overhead}字节)")
    print(f"    SHA256校验和: {checksum}")
    
    # 【已修正】调用新的验证函数
    extract_success, extracted_path, extracted_size = validate_and_extract_dg2_strict(
        dg2, output_path.replace('.bin', '_extracted')
    )
    
    info_content = f"""DG2 Generation Report
---------------------------------
Generation Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Source File:     {image_path}
Output File:     {output_path}
Format:          {format_name}
Dimensions:      {width}x{height}
DG2 Size:        {len(dg2)} bytes
Image Size:      {len(image_data)} bytes
Overhead:        {overhead} bytes
SHA256:          {checksum}
Extraction Test: {'SUCCESS' if extract_success else 'FAILED'}
"""
    
    with open(output_path + ".info", "w", encoding='utf-8') as f:
        f.write(info_content)
    
    print(f"    报告: ✓ 已生成报告文件 -> {output_path}.info")
    return True

def main():
    parser = argparse.ArgumentParser(
        description="生成符合ICAO 9303标准的DG2文件 (JP2000-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python gen_dg2.py photo.jpg --size compact
  python gen_dg2.py C:\\Users\\User\\Desktop\\face.png --out MyDG2.bin --size normal
"""
    )
    parser.add_argument('image', help='输入图像文件路径')
    parser.add_argument('--size', choices=['compact', 'normal', 'quality'],
                       default='compact', help='尺寸模式 (影响目标文件大小)')
    parser.add_argument('--out', default='DG2.bin', help='输出文件路径')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print(f"[错误] 文件不存在: {args.image}")
        sys.exit(1)
    
    generate_dg2_compact(
        args.image, 
        args.out, 
        args.size
    )

if __name__ == '__main__':
    main()
