#!/usr/bin/env python3
"""
Fixed DG2 Generator for Strict Validation
Implements complete ISO/IEC 19794-5 face data format
"""

import os
import struct
from datetime import datetime
from PIL import Image
import io

# DG2 and CBEFF Tags
DG2_TAG = 0x75
BIOMETRIC_INFO_GROUP_TEMPLATE_TAG = 0x7F61
BIOMETRIC_INFO_TEMPLATE_TAG = 0x7F60
BIOMETRIC_HEADER_TEMPLATE_TAG = 0xA1
BIOMETRIC_DATA_BLOCK_TAG = 0x5F2E

# CBEFF Header Tags
CBEFF_PATRON_HEADER_VERSION = 0x80
CBEFF_BDB_FORMAT_OWNER = 0x87
CBEFF_BDB_FORMAT_TYPE = 0x88
CBEFF_BIOMETRIC_TYPE = 0x81
CBEFF_BIOMETRIC_SUBTYPE = 0x82
CBEFF_BDB_CREATION_DATE = 0x85
CBEFF_BDB_VALIDITY_PERIOD = 0x86
CBEFF_CREATOR = 0x89

# ISO/IEC 19794-5 Constants
FORMAT_IDENTIFIER = 0x46414300  # 'FAC\x00'
VERSION_NUMBER = 0x30313000     # '010\x00'
FORMAT_OWNER_VALUE = 0x0101     # ISO/IEC JTC1/SC37
FORMAT_TYPE_VALUE = 0x0008      # Face image data

# Biometric constants
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02
BIOMETRIC_SUBTYPE_NONE = 0x00

# Face image constants
FACE_IMAGE_TYPE_FULL_FRONTAL = 0x01
IMAGE_DATA_TYPE_JPEG = 0x00
IMAGE_COLOR_SPACE_RGB24 = 0x01
SOURCE_TYPE_DIGITAL_CAMERA = 0x02


def encode_length(length):
    """Encode length in BER-TLV format"""
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return struct.pack('>BH', 0x82, length)
    else:
        return struct.pack('>BI', 0x84, length)


def encode_tlv(tag, value):
    """Encode TLV structure"""
    if tag > 0xFF:
        tag_bytes = struct.pack('>H', tag)
    else:
        tag_bytes = bytes([tag])
    
    length_bytes = encode_length(len(value))
    return tag_bytes + length_bytes + value


def create_face_info_block(width, height, image_data):
    """Create ISO/IEC 19794-5 compliant face information block"""
    
    # Calculate lengths
    face_image_data_length = len(image_data)
    face_info_length = 20 + 12 + face_image_data_length  # Info + Image info + Data
    total_record_length = 14 + face_info_length  # Header + Face info
    
    data = io.BytesIO()
    
    # Facial Record Header (14 bytes)
    data.write(struct.pack('>I', FORMAT_IDENTIFIER))  # 'FAC\x00'
    data.write(struct.pack('>I', VERSION_NUMBER))     # '010\x00'
    data.write(struct.pack('>I', total_record_length))
    data.write(struct.pack('>H', 1))  # Number of facial images
    
    # Facial Information Block (20 bytes)
    data.write(struct.pack('>I', face_info_length))  # Record length
    data.write(struct.pack('>H', 0))  # Number of feature points
    data.write(struct.pack('B', 0))   # Gender: unspecified
    data.write(struct.pack('B', 0))   # Eye color: unspecified
    data.write(struct.pack('B', 0))   # Hair color: unspecified
    data.write(b'\x00\x00\x00')       # Feature mask (3 bytes)
    data.write(struct.pack('>H', 0x0001))  # Expression: neutral
    data.write(b'\x00\x00\x00')       # Pose angle (yaw, pitch, roll)
    data.write(b'\x00\x00\x00')       # Pose angle uncertainty
    
    # Face Image Information (12 bytes)
    data.write(struct.pack('B', FACE_IMAGE_TYPE_FULL_FRONTAL))
    data.write(struct.pack('B', IMAGE_DATA_TYPE_JPEG))
    data.write(struct.pack('>H', width))
    data.write(struct.pack('>H', height))
    data.write(struct.pack('B', IMAGE_COLOR_SPACE_RGB24))
    data.write(struct.pack('B', SOURCE_TYPE_DIGITAL_CAMERA))
    data.write(struct.pack('>H', 0))  # Device type ID
    data.write(struct.pack('>H', 100))  # Quality
    
    # Face Image Data
    data.write(image_data)
    
    return data.getvalue()


def create_cbeff_header():
    """Create complete CBEFF header"""
    header = b''
    
    # Patron header version
    header += encode_tlv(CBEFF_PATRON_HEADER_VERSION, bytes([0x01]))
    
    # BDB format owner and type
    header += encode_tlv(CBEFF_BDB_FORMAT_OWNER, struct.pack('>H', FORMAT_OWNER_VALUE))
    header += encode_tlv(CBEFF_BDB_FORMAT_TYPE, struct.pack('>H', FORMAT_TYPE_VALUE))
    
    # Biometric type and subtype
    header += encode_tlv(CBEFF_BIOMETRIC_TYPE, bytes([BIOMETRIC_TYPE_FACIAL_FEATURES]))
    header += encode_tlv(CBEFF_BIOMETRIC_SUBTYPE, bytes([BIOMETRIC_SUBTYPE_NONE]))
    
    # Creation date (current date/time)
    now = datetime.utcnow()
    date_bytes = bytes([
        int(now.strftime('%Y')[:2]), int(now.strftime('%Y')[2:]),
        int(now.strftime('%m')), int(now.strftime('%d')),
        int(now.strftime('%H')), int(now.strftime('%M')),
        int(now.strftime('%S'))
    ])
    header += encode_tlv(CBEFF_BDB_CREATION_DATE, date_bytes)
    
    # Validity period (no expiry)
    header += encode_tlv(CBEFF_BDB_VALIDITY_PERIOD, bytes([0xFF] * 8))
    
    # Creator (18 bytes placeholder)
    creator = b'PASSPORT_GENERATOR' + b'\x00' * (18 - len(b'PASSPORT_GENERATOR'))
    header += encode_tlv(CBEFF_CREATOR, creator[:18])
    
    return header


def generate_strict_dg2(image_path, output_path=None):
    """Generate DG2 file that passes strict validation"""
    
    # Load and prepare image
    img = Image.open(image_path)
    
    # Convert to RGB if necessary
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    # Ensure minimum size (240x320)
    if img.width < 240 or img.height < 320:
        # Scale up maintaining aspect ratio
        scale = max(240 / img.width, 320 / img.height)
        new_width = int(img.width * scale)
        new_height = int(img.height * scale)
        img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    # Convert to JPEG
    jpeg_buffer = io.BytesIO()
    img.save(jpeg_buffer, format='JPEG', quality=90, optimize=True)
    jpeg_data = jpeg_buffer.getvalue()
    
    # Create face info block
    face_data = create_face_info_block(img.width, img.height, jpeg_data)
    
    # Build complete DG2 structure
    # 1. CBEFF header
    cbeff_header = create_cbeff_header()
    cbeff_block = encode_tlv(BIOMETRIC_HEADER_TEMPLATE_TAG, cbeff_header)
    
    # 2. Biometric data block
    bio_data_block = encode_tlv(BIOMETRIC_DATA_BLOCK_TAG, face_data)
    
    # 3. Biometric information template instance
    instance_content = cbeff_block + bio_data_block
    bio_info_instance = encode_tlv(BIOMETRIC_INFO_TEMPLATE_TAG, instance_content)
    
    # 4. Number of instances
    num_instances = encode_tlv(0x02, bytes([1]))
    
    # 5. Biometric information group template
    group_content = num_instances + bio_info_instance
    bio_info_group = encode_tlv(BIOMETRIC_INFO_GROUP_TEMPLATE_TAG, group_content)
    
    # 6. DG2
    dg2 = encode_tlv(DG2_TAG, bio_info_group)
    
    # Save to file
    if output_path is None:
        output_path = 'DG2_strict.bin'
    
    with open(output_path, 'wb') as f:
        f.write(dg2)
    
    print(f"Generated strict DG2 file: {output_path}")
    print(f"File size: {len(dg2)} bytes")
    print(f"Image dimensions: {img.width}x{img.height}")
    
    return dg2


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python gen_dg2_fixed.py <image_path> [output_path]")
        sys.exit(1)
    
    image_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    generate_strict_dg2(image_path, output_path)