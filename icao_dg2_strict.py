#!/usr/bin/env python3
"""
Strict ICAO 9303 DG2 (Data Group 2) Implementation
Based on ISO/IEC 19794-5 and ICAO Doc 9303 standards

This implementation follows the strict validation rules used by official
passport readers and border control systems.
"""

import struct
import io
from typing import List, Tuple, Optional, BinaryIO
from enum import IntEnum
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Constants from ISO/IEC 19794-5
FORMAT_IDENTIFIER = 0x46414300  # 'FAC\x00'
VERSION_NUMBER = 0x30313000     # '010\x00'
FORMAT_OWNER_VALUE = 0x0101     # ISO/IEC JTC1/SC37
FORMAT_TYPE_VALUE = 0x0008      # Face image data

# DG2 Tag
DG2_TAG = 0x75

# CBEFF Tags
CBEFF_PATRON_HEADER_VERSION = 0xA1
CBEFF_BDB_FORMAT_OWNER = 0x87
CBEFF_BDB_FORMAT_TYPE = 0x88
CBEFF_BDB_CREATION_DATE = 0x85
CBEFF_BDB_VALIDITY_PERIOD = 0x86
CBEFF_BIOMETRIC_TYPE = 0x81
CBEFF_BIOMETRIC_SUBTYPE = 0x82
CBEFF_PURPOSE = 0x83
CBEFF_BIOMETRIC_DATA_QUALITY = 0x84
CBEFF_CREATOR = 0x89
CBEFF_BDB_INDEX = 0x8A

# Biometric types
BIOMETRIC_TYPE_FACIAL_FEATURES = 0x02
BIOMETRIC_SUBTYPE_NONE = 0x00

# Image data types
IMAGE_DATA_TYPE_JPEG = 0x00
IMAGE_DATA_TYPE_JPEG2000 = 0x01


class Gender(IntEnum):
    """Gender codes according to ISO/IEC 19794-5"""
    UNSPECIFIED = 0x00
    MALE = 0x01
    FEMALE = 0x02
    UNKNOWN = 0xFF


class EyeColor(IntEnum):
    """Eye color codes according to ISO/IEC 19794-5"""
    UNSPECIFIED = 0x00
    BLACK = 0x01
    BLUE = 0x02
    BROWN = 0x03
    GRAY = 0x04
    GREEN = 0x05
    MULTI_COLORED = 0x06
    PINK = 0x07
    UNKNOWN = 0xFF


class HairColor(IntEnum):
    """Hair color codes according to ISO/IEC 19794-5"""
    UNSPECIFIED = 0x00
    BALD = 0x01
    BLACK = 0x02
    BLONDE = 0x03
    BROWN = 0x04
    GRAY = 0x05
    WHITE = 0x06
    RED = 0x07
    GREEN = 0x08
    BLUE = 0x09
    UNKNOWN = 0xFF


class Expression(IntEnum):
    """Expression codes according to ISO/IEC 19794-5"""
    UNSPECIFIED = 0x0000
    NEUTRAL = 0x0001
    SMILE_CLOSED = 0x0002
    SMILE_OPEN = 0x0003
    RAISED_EYEBROWS = 0x0004
    EYES_LOOKING_AWAY = 0x0005
    SQUINTING = 0x0006
    FROWNING = 0x0007


class FaceImageType(IntEnum):
    """Face image type codes according to ISO/IEC 19794-5"""
    BASIC = 0x00
    FULL_FRONTAL = 0x01
    TOKEN_FRONTAL = 0x02


class ImageColorSpace(IntEnum):
    """Color space codes according to ISO/IEC 19794-5"""
    UNSPECIFIED = 0x00
    RGB24 = 0x01
    YUV422 = 0x02
    GRAY8 = 0x03
    OTHER = 0x04


class SourceType(IntEnum):
    """Source type codes according to ISO/IEC 19794-5"""
    UNSPECIFIED = 0x00
    STATIC_PHOTO_UNKNOWN_SOURCE = 0x01
    STATIC_PHOTO_DIGITAL_CAM = 0x02
    STATIC_PHOTO_SCANNER = 0x03
    VIDEO_FRAME_UNKNOWN_SOURCE = 0x04
    VIDEO_FRAME_ANALOG_CAM = 0x05
    VIDEO_FRAME_DIGITAL_CAM = 0x06
    UNKNOWN = 0x07


@dataclass
class FeaturePoint:
    """Feature point structure according to ISO/IEC 19794-5"""
    type: int
    major: int
    minor: int
    x: int
    y: int
    reserved: int = 0


@dataclass
class FaceImageInfo:
    """Face image information according to ISO/IEC 19794-5"""
    # Facial Information Block
    gender: Gender
    eye_color: EyeColor
    hair_color: HairColor
    feature_mask: int  # 3 bytes
    expression: Expression
    pose_angle: Tuple[int, int, int]  # yaw, pitch, roll
    pose_angle_uncertainty: Tuple[int, int, int]
    
    # Feature points
    feature_points: List[FeaturePoint]
    
    # Face Image Information
    face_image_type: FaceImageType
    image_data_type: int
    width: int
    height: int
    color_space: ImageColorSpace
    source_type: SourceType
    device_type: int  # 2 bytes
    quality: int  # 2 bytes
    
    # Image data
    image_data: bytes
    
    def get_record_length(self) -> int:
        """Calculate the total record length"""
        # Facial Information Block (20 bytes) + Feature Points + Face Image Info (12 bytes) + Image Data
        return 20 + (8 * len(self.feature_points)) + 12 + len(self.image_data)
    
    def write(self, output: BinaryIO) -> None:
        """Write face image info to output stream"""
        record_length = self.get_record_length()
        
        # Facial Information Block (20 bytes)
        output.write(struct.pack('>I', record_length))  # 4 bytes
        output.write(struct.pack('>H', len(self.feature_points)))  # 2 bytes
        output.write(struct.pack('B', self.gender))  # 1 byte
        output.write(struct.pack('B', self.eye_color))  # 1 byte
        output.write(struct.pack('B', self.hair_color))  # 1 byte
        output.write(struct.pack('>I', self.feature_mask)[1:])  # 3 bytes (skip MSB)
        output.write(struct.pack('>H', self.expression))  # 2 bytes
        
        # Pose angles (3 bytes each)
        for angle in self.pose_angle:
            output.write(struct.pack('B', angle))
        for uncertainty in self.pose_angle_uncertainty:
            output.write(struct.pack('B', uncertainty))
        
        # Feature points (8 bytes each)
        for fp in self.feature_points:
            output.write(struct.pack('B', fp.type))
            output.write(struct.pack('B', (fp.major << 4) | fp.minor))
            output.write(struct.pack('>H', fp.x))
            output.write(struct.pack('>H', fp.y))
            output.write(struct.pack('>H', fp.reserved))
        
        # Face Image Information (12 bytes)
        output.write(struct.pack('B', self.face_image_type))
        output.write(struct.pack('B', self.image_data_type))
        output.write(struct.pack('>H', self.width))
        output.write(struct.pack('>H', self.height))
        output.write(struct.pack('B', self.color_space))
        output.write(struct.pack('B', self.source_type))
        output.write(struct.pack('>H', self.device_type))
        output.write(struct.pack('>H', self.quality))
        
        # Image data
        output.write(self.image_data)
    
    @classmethod
    def read(cls, input_stream: BinaryIO) -> 'FaceImageInfo':
        """Read face image info from input stream"""
        # Read Facial Information Block
        record_length = struct.unpack('>I', input_stream.read(4))[0]
        feature_point_count = struct.unpack('>H', input_stream.read(2))[0]
        gender = Gender(struct.unpack('B', input_stream.read(1))[0])
        eye_color = EyeColor(struct.unpack('B', input_stream.read(1))[0])
        hair_color = struct.unpack('B', input_stream.read(1))[0]
        feature_mask = struct.unpack('>I', b'\x00' + input_stream.read(3))[0]
        expression = Expression(struct.unpack('>H', input_stream.read(2))[0])
        
        # Read pose angles
        pose_angle = tuple(struct.unpack('B', input_stream.read(1))[0] for _ in range(3))
        pose_angle_uncertainty = tuple(struct.unpack('B', input_stream.read(1))[0] for _ in range(3))
        
        # Read feature points
        feature_points = []
        for _ in range(feature_point_count):
            fp_type = struct.unpack('B', input_stream.read(1))[0]
            major_minor = struct.unpack('B', input_stream.read(1))[0]
            major = (major_minor >> 4) & 0x0F
            minor = major_minor & 0x0F
            x = struct.unpack('>H', input_stream.read(2))[0]
            y = struct.unpack('>H', input_stream.read(2))[0]
            reserved = struct.unpack('>H', input_stream.read(2))[0]
            feature_points.append(FeaturePoint(fp_type, major, minor, x, y, reserved))
        
        # Read Face Image Information
        face_image_type = FaceImageType(struct.unpack('B', input_stream.read(1))[0])
        image_data_type = struct.unpack('B', input_stream.read(1))[0]
        width = struct.unpack('>H', input_stream.read(2))[0]
        height = struct.unpack('>H', input_stream.read(2))[0]
        color_space = ImageColorSpace(struct.unpack('B', input_stream.read(1))[0])
        source_type = SourceType(struct.unpack('B', input_stream.read(1))[0])
        device_type = struct.unpack('>H', input_stream.read(2))[0]
        quality = struct.unpack('>H', input_stream.read(2))[0]
        
        # Calculate image data length
        header_length = 20 + (8 * feature_point_count) + 12
        image_length = record_length - header_length
        
        # Read image data
        image_data = input_stream.read(image_length)
        
        return cls(
            gender=gender,
            eye_color=eye_color,
            hair_color=hair_color,
            feature_mask=feature_mask,
            expression=expression,
            pose_angle=pose_angle,
            pose_angle_uncertainty=pose_angle_uncertainty,
            feature_points=feature_points,
            face_image_type=face_image_type,
            image_data_type=image_data_type,
            width=width,
            height=height,
            color_space=color_space,
            source_type=source_type,
            device_type=device_type,
            quality=quality,
            image_data=image_data
        )


class FaceInfo:
    """Face information structure according to ISO/IEC 19794-5"""
    
    def __init__(self, face_image_infos: List[FaceImageInfo]):
        self.face_image_infos = face_image_infos
    
    def get_record_length(self) -> int:
        """Calculate total record length"""
        header_length = 14  # 4 + 4 + 4 + 2
        data_length = sum(info.get_record_length() for info in self.face_image_infos)
        return header_length + data_length
    
    def write(self, output: BinaryIO) -> None:
        """Write face info to output stream"""
        record_length = self.get_record_length()
        
        # Write header
        output.write(struct.pack('>I', FORMAT_IDENTIFIER))  # 4 bytes
        output.write(struct.pack('>I', VERSION_NUMBER))     # 4 bytes
        output.write(struct.pack('>I', record_length))      # 4 bytes
        output.write(struct.pack('>H', len(self.face_image_infos)))  # 2 bytes
        
        # Write face image infos
        for info in self.face_image_infos:
            info.write(output)
    
    @classmethod
    def read(cls, input_stream: BinaryIO) -> 'FaceInfo':
        """Read face info from input stream"""
        # Read header
        format_id = struct.unpack('>I', input_stream.read(4))[0]
        if format_id != FORMAT_IDENTIFIER:
            raise ValueError(f"Invalid format identifier: 0x{format_id:08X}")
        
        version = struct.unpack('>I', input_stream.read(4))[0]
        if version != VERSION_NUMBER:
            raise ValueError(f"Invalid version number: 0x{version:08X}")
        
        record_length = struct.unpack('>I', input_stream.read(4))[0]
        count = struct.unpack('>H', input_stream.read(2))[0]
        
        # Read face image infos
        face_image_infos = []
        for _ in range(count):
            info = FaceImageInfo.read(input_stream)
            face_image_infos.append(info)
        
        return cls(face_image_infos)


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode data in TLV (Tag-Length-Value) format"""
    # Encode tag
    if tag <= 0x7F:
        tag_bytes = bytes([tag])
    elif tag <= 0xFF:
        tag_bytes = bytes([0x5F, tag])
    else:
        # Multi-byte tag
        tag_bytes = bytes([tag >> 8, tag & 0xFF])
    
    # Encode length
    length = len(value)
    if length <= 0x7F:
        length_bytes = bytes([length])
    elif length <= 0xFF:
        length_bytes = bytes([0x81, length])
    elif length <= 0xFFFF:
        length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        # Long form (3 bytes)
        length_bytes = bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    
    return tag_bytes + length_bytes + value


def decode_tlv(data: bytes) -> List[Tuple[int, bytes]]:
    """Decode TLV (Tag-Length-Value) format data"""
    result = []
    offset = 0
    
    while offset < len(data):
        # Read tag
        tag = data[offset]
        offset += 1
        
        if tag == 0x5F:  # Multi-byte tag
            tag = (tag << 8) | data[offset]
            offset += 1
        elif (tag & 0x1F) == 0x1F:  # Multi-byte tag
            while data[offset] & 0x80:
                tag = (tag << 8) | data[offset]
                offset += 1
            tag = (tag << 8) | data[offset]
            offset += 1
        
        # Read length
        length = data[offset]
        offset += 1
        
        if length & 0x80:  # Long form
            num_octets = length & 0x7F
            length = 0
            for _ in range(num_octets):
                length = (length << 8) | data[offset]
                offset += 1
        
        # Read value
        value = data[offset:offset + length]
        offset += length
        
        result.append((tag, value))
    
    return result


class DG2File:
    """DG2 (Data Group 2) file structure according to ICAO 9303"""
    
    def __init__(self, face_info: FaceInfo):
        self.face_info = face_info
    
    def encode(self) -> bytes:
        """Encode DG2 file to bytes"""
        # Create biometric data block
        bio_data = io.BytesIO()
        self.face_info.write(bio_data)
        bio_data_bytes = bio_data.getvalue()
        
        # Create biometric information template
        # Tag 0x7F61 - Biometric Information Template
        bio_info_content = b''
        
        # Tag 0x02 - Number of instances (1 byte)
        bio_info_content += encode_tlv(0x02, bytes([len(self.face_info.face_image_infos)]))
        
        # Tag 0x7F60 - Biometric Information Template for each instance
        for i, face_image in enumerate(self.face_info.face_image_infos):
            instance_content = b''
            
            # Tag 0xA1 - CBEFF Product Identifier
            cbeff_header = b''
            cbeff_header += encode_tlv(CBEFF_PATRON_HEADER_VERSION, bytes([0x01]))
            cbeff_header += encode_tlv(CBEFF_BDB_FORMAT_OWNER, struct.pack('>H', FORMAT_OWNER_VALUE))
            cbeff_header += encode_tlv(CBEFF_BDB_FORMAT_TYPE, struct.pack('>H', FORMAT_TYPE_VALUE))
            cbeff_header += encode_tlv(CBEFF_BIOMETRIC_TYPE, bytes([BIOMETRIC_TYPE_FACIAL_FEATURES]))
            cbeff_header += encode_tlv(CBEFF_BIOMETRIC_SUBTYPE, bytes([BIOMETRIC_SUBTYPE_NONE]))
            cbeff_header += encode_tlv(CBEFF_BDB_CREATION_DATE, bytes(7))  # Placeholder
            cbeff_header += encode_tlv(CBEFF_BDB_VALIDITY_PERIOD, bytes([0xFF] * 8))  # No expiry
            cbeff_header += encode_tlv(CBEFF_CREATOR, bytes(18))  # Placeholder
            
            instance_content += encode_tlv(0xA1, cbeff_header)
            
            # Tag 0x5F2E or 0x7F2E - Biometric data block
            # For first instance use 0x5F2E, for others use 0x7F2E
            bdb_tag = 0x5F2E if i == 0 else 0x7F2E
            
            # Create individual face data
            face_data = io.BytesIO()
            face_data.write(struct.pack('>I', FORMAT_IDENTIFIER))
            face_data.write(struct.pack('>I', VERSION_NUMBER))
            face_data.write(struct.pack('>I', 14 + face_image.get_record_length()))
            face_data.write(struct.pack('>H', 1))  # Single face image
            face_image.write(face_data)
            
            instance_content += encode_tlv(bdb_tag, face_data.getvalue())
            
            bio_info_content += encode_tlv(0x7F60, instance_content)
        
        # Wrap in tag 0x7F61
        bio_info_template = encode_tlv(0x7F61, bio_info_content)
        
        # Wrap in DG2 tag 0x75
        dg2_content = encode_tlv(DG2_TAG, bio_info_template)
        
        return dg2_content
    
    @classmethod
    def decode(cls, data: bytes) -> 'DG2File':
        """Decode DG2 file from bytes"""
        # Parse outer TLV
        tlvs = decode_tlv(data)
        if not tlvs or tlvs[0][0] != DG2_TAG:
            raise ValueError("Invalid DG2 file: missing or wrong tag")
        
        # Parse biometric information template
        bio_info_tlvs = decode_tlv(tlvs[0][1])
        if not bio_info_tlvs or bio_info_tlvs[0][0] != 0x7F61:
            raise ValueError("Invalid DG2 file: missing biometric information template")
        
        # Parse content
        content_tlvs = decode_tlv(bio_info_tlvs[0][1])
        
        # Find biometric data blocks
        face_image_infos = []
        
        for tag, value in content_tlvs:
            if tag == 0x7F60:  # Biometric Information Template instance
                instance_tlvs = decode_tlv(value)
                for inst_tag, inst_value in instance_tlvs:
                    if inst_tag in (0x5F2E, 0x7F2E):  # Biometric data block
                        # Parse face info
                        face_info = FaceInfo.read(io.BytesIO(inst_value))
                        face_image_infos.extend(face_info.face_image_infos)
        
        if not face_image_infos:
            raise ValueError("No face image data found in DG2")
        
        return cls(FaceInfo(face_image_infos))


def validate_dg2_strict(dg2_data: bytes) -> Tuple[bool, List[str]]:
    """
    Perform strict validation of DG2 data according to ICAO 9303 standards
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    try:
        # Basic structure validation
        if len(dg2_data) < 100:
            errors.append("DG2 data too short (minimum 100 bytes expected)")
            return False, errors
        
        # Check DG2 tag
        if dg2_data[0] != DG2_TAG:
            errors.append(f"Invalid DG2 tag: expected 0x{DG2_TAG:02X}, got 0x{dg2_data[0]:02X}")
            return False, errors
        
        # Decode DG2
        dg2 = DG2File.decode(dg2_data)
        
        # Validate face info
        if not dg2.face_info.face_image_infos:
            errors.append("No face images found in DG2")
            return False, errors
        
        for i, face_image in enumerate(dg2.face_info.face_image_infos):
            # Validate image dimensions
            if face_image.width < 90 or face_image.height < 120:
                errors.append(f"Face image {i}: dimensions too small ({face_image.width}x{face_image.height})")
            
            # Validate image type
            if face_image.face_image_type not in [FaceImageType.FULL_FRONTAL, FaceImageType.TOKEN_FRONTAL]:
                errors.append(f"Face image {i}: invalid face image type")
            
            # Validate image data type
            if face_image.image_data_type not in [IMAGE_DATA_TYPE_JPEG, IMAGE_DATA_TYPE_JPEG2000]:
                errors.append(f"Face image {i}: invalid image data type")
            
            # Validate expression (should be neutral for passport photos)
            if face_image.expression not in [Expression.NEUTRAL, Expression.UNSPECIFIED]:
                errors.append(f"Face image {i}: non-neutral expression")
            
            # Validate pose angles (should be near zero)
            yaw, pitch, roll = face_image.pose_angle
            if abs(yaw) > 5 or abs(pitch) > 5 or abs(roll) > 5:
                errors.append(f"Face image {i}: excessive pose angles (yaw={yaw}, pitch={pitch}, roll={roll})")
            
            # Validate quality
            if face_image.quality < 50:
                errors.append(f"Face image {i}: low quality score ({face_image.quality})")
            
            # Validate image data
            if not face_image.image_data:
                errors.append(f"Face image {i}: missing image data")
            elif len(face_image.image_data) < 1000:
                errors.append(f"Face image {i}: image data too small")
            
            # Check JPEG/JPEG2000 markers
            if face_image.image_data_type == IMAGE_DATA_TYPE_JPEG:
                if not face_image.image_data.startswith(b'\xFF\xD8'):
                    errors.append(f"Face image {i}: invalid JPEG header")
            elif face_image.image_data_type == IMAGE_DATA_TYPE_JPEG2000:
                if not (face_image.image_data.startswith(b'\x00\x00\x00\x0C') or 
                        face_image.image_data.startswith(b'\xFF\x4F\xFF\x51')):
                    errors.append(f"Face image {i}: invalid JPEG2000 header")
        
        return len(errors) == 0, errors
        
    except Exception as e:
        errors.append(f"DG2 parsing error: {str(e)}")
        return False, errors


def create_minimal_dg2(image_data: bytes, image_type: int = IMAGE_DATA_TYPE_JPEG,
                      width: int = 240, height: int = 320) -> bytes:
    """
    Create a minimal but strictly compliant DG2 structure
    
    Args:
        image_data: JPEG or JPEG2000 image data
        image_type: IMAGE_DATA_TYPE_JPEG or IMAGE_DATA_TYPE_JPEG2000
        width: Image width in pixels
        height: Image height in pixels
    
    Returns:
        Encoded DG2 data
    """
    # Create face image info with minimal required data
    face_image = FaceImageInfo(
        gender=Gender.UNSPECIFIED,
        eye_color=EyeColor.UNSPECIFIED,
        hair_color=HairColor.UNSPECIFIED,
        feature_mask=0x000001,  # Features are specified
        expression=Expression.NEUTRAL,
        pose_angle=(0, 0, 0),  # Frontal pose
        pose_angle_uncertainty=(0, 0, 0),
        feature_points=[],  # No feature points
        face_image_type=FaceImageType.FULL_FRONTAL,
        image_data_type=image_type,
        width=width,
        height=height,
        color_space=ImageColorSpace.RGB24,
        source_type=SourceType.STATIC_PHOTO_DIGITAL_CAM,
        device_type=0x0000,  # Unspecified
        quality=100,  # Maximum quality
        image_data=image_data
    )
    
    # Create face info
    face_info = FaceInfo([face_image])
    
    # Create DG2 file
    dg2 = DG2File(face_info)
    
    # Encode and return
    return dg2.encode()


# Example usage
if __name__ == "__main__":
    # Example: Create a minimal DG2 with dummy JPEG data
    dummy_jpeg = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + b'\x00' * 1000 + b'\xFF\xD9'
    
    # Create DG2
    dg2_data = create_minimal_dg2(dummy_jpeg, IMAGE_DATA_TYPE_JPEG, 240, 320)
    
    # Validate
    is_valid, errors = validate_dg2_strict(dg2_data)
    
    print(f"DG2 size: {len(dg2_data)} bytes")
    print(f"Valid: {is_valid}")
    if errors:
        print("Errors:")
        for error in errors:
            print(f"  - {error}")
    
    # Save to file
    with open("strict_dg2.bin", "wb") as f:
        f.write(dg2_data)
    
    print("\nStrict DG2 saved to strict_dg2.bin")