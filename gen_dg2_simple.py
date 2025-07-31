#!/usr/bin/env python3
"""
Simplified DG2 Generator - Creates ICAO 9303 compliant DG2 files without face detection
"""

import os
import sys
import argparse
import struct
import hashlib
from datetime import datetime, timezone, timedelta
from PIL import Image
import numpy as np
from io import BytesIO

# DG2 Structure Tags
DG2_TAG = 0x75
BIOMETRIC_INFO_GROUP_TEMPLATE_TAG = 0x7F61
BIOMETRIC_INFO_TEMPLATE_TAG = 0x7F60
BIOMETRIC_HEADER_TEMPLATE_TAG = 0xA1
BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E

# Biometric Header Tags
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

# Constants
CBEFF_PATRON_HEADER_VERSION = 0x0101
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02
BIOMETRIC_SUBTYPE_NO_INFO = 0x00
DEFAULT_VALIDITY_YEARS = 10
FORMAT_OWNER_ICAO = 0x0101
FORMAT_TYPE_FACIAL_JPG = 0x0007
FORMAT_TYPE_FACIAL_JP2 = 0x0008

# Image sizes
PASSPORT_PHOTO_SIZES = [
    (300, 400),
    (360, 480),
    (420, 560),
    (480, 640),
]

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
        raise ValueError(f"Value must be bytes, got {type(value)}")
    
    # Encode tag
    if tag <= 0xFF:
        tag_bytes = bytes([tag])
    elif tag <= 0xFFFF:
        tag_bytes = tag.to_bytes(2, 'big')
    else:
        tag_bytes = tag.to_bytes(3, 'big')
    
    # Encode length and combine
    length_bytes = encode_length(len(value))
    return tag_bytes + length_bytes + value

def generate_feature_points_simple(width: int, height: int) -> bytes:
    """Generate simple facial feature points without face detection"""
    # Generate approximate positions for facial features
    # Based on typical facial proportions
    
    feature_points = []
    
    # Left eye center (approximate)
    left_eye_x = int(width * 0.35)
    left_eye_y = int(height * 0.35)
    feature_points.append((0x01, 0x01, 0x00, left_eye_x, left_eye_y))
    
    # Right eye center (approximate)
    right_eye_x = int(width * 0.65)
    right_eye_y = int(height * 0.35)
    feature_points.append((0x01, 0x02, 0x00, right_eye_x, right_eye_y))
    
    # Nose tip (approximate)
    nose_x = int(width * 0.50)
    nose_y = int(height * 0.50)
    feature_points.append((0x01, 0x03, 0x00, nose_x, nose_y))
    
    # Mouth center (approximate)
    mouth_x = int(width * 0.50)
    mouth_y = int(height * 0.65)
    feature_points.append((0x01, 0x04, 0x00, mouth_x, mouth_y))
    
    # Encode feature points
    encoded_points = b''
    for point_type, major, minor, x, y in feature_points:
        encoded_points += struct.pack('>BBBHHB', point_type, major, minor, x, y, 0x00)
    
    return encoded_points

def resize_image_for_dg2(image_path: str, size_mode: str = 'compact') -> tuple:
    """Resize image to appropriate passport photo size"""
    img = Image.open(image_path)
    
    # Convert to RGB if necessary
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    # Select target size based on mode
    if size_mode == 'compact':
        target_size = PASSPORT_PHOTO_SIZES[0]  # 300x400
    elif size_mode == 'normal':
        target_size = PASSPORT_PHOTO_SIZES[1]  # 360x480
    else:  # quality
        target_size = PASSPORT_PHOTO_SIZES[2]  # 420x560
    
    # Resize maintaining aspect ratio
    img.thumbnail(target_size, Image.Resampling.LANCZOS)
    
    # Create new image with exact target size (add white padding if needed)
    new_img = Image.new('RGB', target_size, 'white')
    
    # Paste resized image centered
    x_offset = (target_size[0] - img.width) // 2
    y_offset = (target_size[1] - img.height) // 2
    new_img.paste(img, (x_offset, y_offset))
    
    return new_img, target_size[0], target_size[1]

def generate_dg2(image_path: str, output_path: str, size_mode: str = 'compact'):
    """Generate DG2 file from image"""
    print(f"[生成DG2] 输入图像: {image_path}")
    
    # Resize image
    img, width, height = resize_image_for_dg2(image_path, size_mode)
    
    # Convert to JPEG
    buffer = BytesIO()
    img.save(buffer, format='JPEG', quality=90)
    image_data = buffer.getvalue()
    
    print(f"[处理] 图像尺寸: {width}x{height}")
    print(f"[处理] JPEG 数据大小: {len(image_data)} 字节")
    
    # Generate timestamps
    now = datetime.now(timezone.utc)
    creation_date = now.strftime('%Y%m%d%H%M%SZ').encode('ascii')
    
    valid_from = now.strftime('%Y%m%d').encode('ascii')
    valid_to = (now + timedelta(days=365 * DEFAULT_VALIDITY_YEARS)).strftime('%Y%m%d').encode('ascii')
    validity_period = valid_from + valid_to
    
    # Generate feature points
    feature_points = generate_feature_points_simple(width, height)
    
    # Build biometric header template
    header_fields = [
        encode_tlv(ICAO_HEADER_VERSION_TAG, struct.pack('>BB', 0x01, 0x01)),
        encode_tlv(BIOMETRIC_TYPE_TAG, bytes([BIOMETRIC_TYPE_FACIAL_FEATURES])),
        encode_tlv(BIOMETRIC_SUBTYPE_TAG, bytes([BIOMETRIC_SUBTYPE_NO_INFO])),
        encode_tlv(CREATION_DATE_TIME_TAG, creation_date),
        encode_tlv(VALIDITY_PERIOD_TAG, validity_period),
        encode_tlv(CREATOR_TAG, b'SimpleDG2Gen'),
        encode_tlv(FORMAT_OWNER_TAG, struct.pack('>H', FORMAT_OWNER_ICAO)),
        encode_tlv(FORMAT_TYPE_TAG, struct.pack('>H', FORMAT_TYPE_FACIAL_JPG)),
        encode_tlv(IMAGE_WIDTH_TAG, struct.pack('>H', width)),
        encode_tlv(IMAGE_HEIGHT_TAG, struct.pack('>H', height)),
        encode_tlv(FEATURE_POINTS_TAG, feature_points),
    ]
    
    header_content = b''.join(header_fields)
    biometric_header = encode_tlv(BIOMETRIC_HEADER_TEMPLATE_TAG, header_content)
    
    # Build biometric data block
    biometric_data = encode_tlv(BIOMETRIC_DATA_BLOCK_TAG, image_data)
    
    # Build biometric info template
    biometric_info_content = biometric_header + biometric_data
    biometric_info_template = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, biometric_info_content)
    
    # Build biometric info group template
    sample_number = encode_tlv(SAMPLE_NUMBER_TAG, bytes([0x01]))
    biometric_info_group_content = sample_number + biometric_info_template
    biometric_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, biometric_info_group_content)
    
    # Build final DG2 structure
    dg2 = encode_tlv(DG2_TAG, biometric_info_group)
    
    # Save DG2 file
    with open(output_path, 'wb') as f:
        f.write(dg2)
    
    # Calculate and display statistics
    overhead = len(dg2) - len(image_data)
    checksum = hashlib.sha256(dg2).hexdigest()
    
    print(f"[成功] DG2 文件已生成: {output_path}")
    print(f"[统计] 总大小: {len(dg2)} 字节")
    print(f"[统计] 数据开销: {overhead} 字节")
    print(f"[统计] SHA256: {checksum}")
    
    # Generate info file
    info_content = f"""DG2 Generation Report
=================================
Generation Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Source File:     {image_path}
Output File:     {output_path}
Format:          JPEG
Dimensions:      {width}x{height}
DG2 Size:        {len(dg2)} bytes
Image Size:      {len(image_data)} bytes
Overhead:        {overhead} bytes
SHA256:          {checksum}
Feature Points:  4 (approximate positions)
"""
    
    with open(output_path + '.info', 'w', encoding='utf-8') as f:
        f.write(info_content)
    
    print(f"[报告] 信息文件已生成: {output_path}.info")

def main():
    parser = argparse.ArgumentParser(
        description="简化版 DG2 生成器 - 生成符合 ICAO 9303 标准的 DG2 文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python gen_dg2_simple.py photo.jpg
  python gen_dg2_simple.py photo.jpg --size normal --out MyDG2.bin
"""
    )
    
    parser.add_argument('image', help='输入图像文件路径')
    parser.add_argument('--size', choices=['compact', 'normal', 'quality'],
                       default='compact', help='尺寸模式')
    parser.add_argument('--out', default='DG2.bin', help='输出文件路径')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print(f"[错误] 文件不存在: {args.image}")
        sys.exit(1)
    
    generate_dg2(args.image, args.out, args.size)

if __name__ == '__main__':
    main()