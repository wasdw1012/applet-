#!/usr/bin/env python3
"""
Strict ICAO 9303 DG2 Generator
Creates DG2 files that pass the most strict validation checks

This generator creates DG2 files that are fully compliant with:
- ICAO Doc 9303 Part 10 (Logical Data Structure)
- ISO/IEC 19794-5:2005 (Face image data)
- ISO/IEC 19785-1:2006 (Common Biometric Exchange Formats Framework - CBEFF)
"""

import os
import sys
import argparse
import hashlib
from datetime import datetime
from PIL import Image
import io
import struct

# Import our strict DG2 implementation
from icao_dg2_strict import (
    DG2File, FaceInfo, FaceImageInfo, 
    Gender, EyeColor, HairColor, Expression,
    FaceImageType, ImageColorSpace, SourceType,
    IMAGE_DATA_TYPE_JPEG, IMAGE_DATA_TYPE_JPEG2000,
    create_minimal_dg2, validate_dg2_strict
)


def convert_image_to_jpeg(image_path: str, max_size: int = 20000, 
                         target_width: int = 240, target_height: int = 320) -> bytes:
    """
    Convert image to JPEG format optimized for passport photos
    
    Args:
        image_path: Path to input image
        max_size: Maximum file size in bytes
        target_width: Target width (ICAO recommends 240-480 pixels)
        target_height: Target height (ICAO recommends 320-640 pixels)
    
    Returns:
        JPEG encoded image data
    """
    # Open and convert image
    img = Image.open(image_path)
    
    # Convert to RGB if necessary
    if img.mode not in ('RGB', 'L'):
        img = img.convert('RGB')
    
    # Calculate aspect ratio
    aspect = img.width / img.height
    target_aspect = target_width / target_height
    
    # Resize to fit target dimensions while maintaining aspect ratio
    if aspect > target_aspect:
        # Image is wider than target
        new_width = target_width
        new_height = int(target_width / aspect)
    else:
        # Image is taller than target
        new_height = target_height
        new_width = int(target_height * aspect)
    
    # Ensure minimum dimensions (ICAO requirement)
    if new_width < 240:
        scale = 240 / new_width
        new_width = 240
        new_height = int(new_height * scale)
    if new_height < 320:
        scale = 320 / new_height
        new_height = 320
        new_width = int(new_width * scale)
    
    # Resize image
    img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    # Find optimal JPEG quality
    quality = 95
    while quality > 30:
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=quality, optimize=True)
        jpeg_data = buffer.getvalue()
        
        if len(jpeg_data) <= max_size:
            break
        
        quality -= 5
    
    return jpeg_data, new_width, new_height


def convert_image_to_jpeg2000(image_path: str, max_size: int = 20000,
                             target_width: int = 240, target_height: int = 320) -> bytes:
    """
    Convert image to JPEG2000 format
    
    Note: Requires OpenJPEG or similar JPEG2000 codec
    """
    try:
        import glymur
        
        # Open and convert image
        img = Image.open(image_path)
        
        # Convert to RGB if necessary
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')
        
        # Resize similar to JPEG
        aspect = img.width / img.height
        target_aspect = target_width / target_height
        
        if aspect > target_aspect:
            new_width = target_width
            new_height = int(target_width / aspect)
        else:
            new_height = target_height
            new_width = int(target_height * aspect)
        
        # Ensure minimum dimensions
        if new_width < 240:
            scale = 240 / new_width
            new_width = 240
            new_height = int(new_height * scale)
        if new_height < 320:
            scale = 320 / new_height
            new_height = 320
            new_width = int(new_width * scale)
        
        img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Convert to numpy array
        import numpy as np
        img_array = np.array(img)
        
        # Save as JPEG2000
        temp_file = "temp_jp2.jp2"
        glymur.Jp2k(temp_file, img_array)
        
        # Read back the data
        with open(temp_file, 'rb') as f:
            jp2_data = f.read()
        
        # Clean up
        os.remove(temp_file)
        
        return jp2_data, new_width, new_height
        
    except ImportError:
        print("Warning: JPEG2000 support requires 'glymur' package")
        print("Falling back to JPEG format")
        return None, 0, 0


def generate_strict_dg2(image_path: str, output_path: str = 'DG2_strict.bin',
                       format_type: str = 'jpeg', 
                       gender: str = 'unspecified',
                       quality: int = 100) -> bool:
    """
    Generate a strictly compliant DG2 file
    
    Args:
        image_path: Path to input image
        output_path: Path for output DG2 file
        format_type: 'jpeg' or 'jpeg2000'
        gender: 'male', 'female', or 'unspecified'
        quality: Quality score (0-100)
    
    Returns:
        True if successful
    """
    print(f"Generating strict DG2 from: {image_path}")
    
    # Determine image format
    if format_type.lower() == 'jpeg2000':
        image_data, width, height = convert_image_to_jpeg2000(image_path)
        if image_data is None:
            # Fallback to JPEG
            image_data, width, height = convert_image_to_jpeg(image_path)
            image_data_type = IMAGE_DATA_TYPE_JPEG
        else:
            image_data_type = IMAGE_DATA_TYPE_JPEG2000
    else:
        image_data, width, height = convert_image_to_jpeg(image_path)
        image_data_type = IMAGE_DATA_TYPE_JPEG
    
    print(f"  Image format: {'JPEG' if image_data_type == IMAGE_DATA_TYPE_JPEG else 'JPEG2000'}")
    print(f"  Dimensions: {width}x{height}")
    print(f"  Size: {len(image_data)} bytes")
    
    # Map gender
    gender_map = {
        'male': Gender.MALE,
        'female': Gender.FEMALE,
        'unspecified': Gender.UNSPECIFIED
    }
    gender_value = gender_map.get(gender.lower(), Gender.UNSPECIFIED)
    
    # Create face image info with strict compliance
    face_image = FaceImageInfo(
        # Facial Information Block
        gender=gender_value,
        eye_color=EyeColor.UNSPECIFIED,
        hair_color=HairColor.UNSPECIFIED,
        feature_mask=0x000001,  # Features are specified flag
        expression=Expression.NEUTRAL,  # Must be neutral for passport
        pose_angle=(0, 0, 0),  # Frontal pose (yaw, pitch, roll)
        pose_angle_uncertainty=(0, 0, 0),  # No uncertainty
        
        # No feature points (optional in DG2)
        feature_points=[],
        
        # Face Image Information
        face_image_type=FaceImageType.FULL_FRONTAL,  # Required for passport
        image_data_type=image_data_type,
        width=width,
        height=height,
        color_space=ImageColorSpace.RGB24,  # Standard color space
        source_type=SourceType.STATIC_PHOTO_DIGITAL_CAM,  # Digital camera
        device_type=0x0000,  # Unspecified device
        quality=quality,  # Quality score
        
        # Image data
        image_data=image_data
    )
    
    # Create face info (can contain multiple faces, but passport typically has one)
    face_info = FaceInfo([face_image])
    
    # Create DG2 file
    dg2 = DG2File(face_info)
    
    # Encode DG2
    dg2_data = dg2.encode()
    
    # Validate before saving
    is_valid, errors = validate_dg2_strict(dg2_data)
    
    if not is_valid:
        print("\nValidation errors:")
        for error in errors:
            print(f"  - {error}")
        return False
    
    # Save DG2 file
    with open(output_path, 'wb') as f:
        f.write(dg2_data)
    
    # Calculate hash
    dg2_hash = hashlib.sha256(dg2_data).hexdigest()
    
    print(f"\nDG2 generated successfully:")
    print(f"  File: {output_path}")
    print(f"  Size: {len(dg2_data)} bytes")
    print(f"  SHA256: {dg2_hash}")
    print(f"  Valid: {is_valid}")
    
    # Generate info file
    info_path = output_path.replace('.bin', '_info.txt')
    with open(info_path, 'w') as f:
        f.write(f"DG2 File Information\n")
        f.write(f"===================\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Source image: {os.path.basename(image_path)}\n")
        f.write(f"DG2 file: {os.path.basename(output_path)}\n")
        f.write(f"DG2 size: {len(dg2_data)} bytes\n")
        f.write(f"SHA256: {dg2_hash}\n\n")
        f.write(f"Image Information:\n")
        f.write(f"  Format: {'JPEG' if image_data_type == IMAGE_DATA_TYPE_JPEG else 'JPEG2000'}\n")
        f.write(f"  Dimensions: {width}x{height} pixels\n")
        f.write(f"  Size: {len(image_data)} bytes\n")
        f.write(f"  Color space: RGB24\n")
        f.write(f"  Face type: Full frontal\n")
        f.write(f"  Expression: Neutral\n")
        f.write(f"  Quality: {quality}\n\n")
        f.write(f"Validation: {'PASSED' if is_valid else 'FAILED'}\n")
        if errors:
            f.write(f"Errors:\n")
            for error in errors:
                f.write(f"  - {error}\n")
    
    print(f"  Info file: {info_path}")
    
    return True


def extract_and_save_image_from_dg2(dg2_path: str, output_prefix: str = "extracted") -> bool:
    """
    Extract and save face image from DG2 file
    
    Args:
        dg2_path: Path to DG2 file
        output_prefix: Prefix for output image files
    
    Returns:
        True if successful
    """
    try:
        # Read DG2 file
        with open(dg2_path, 'rb') as f:
            dg2_data = f.read()
        
        # Decode DG2
        dg2 = DG2File.decode(dg2_data)
        
        # Extract face images
        for i, face_image in enumerate(dg2.face_info.face_image_infos):
            # Determine file extension
            if face_image.image_data_type == IMAGE_DATA_TYPE_JPEG:
                ext = 'jpg'
            elif face_image.image_data_type == IMAGE_DATA_TYPE_JPEG2000:
                ext = 'jp2'
            else:
                ext = 'bin'
            
            # Save image
            output_path = f"{output_prefix}_{i}.{ext}"
            with open(output_path, 'wb') as f:
                f.write(face_image.image_data)
            
            print(f"Extracted image {i}:")
            print(f"  File: {output_path}")
            print(f"  Format: {'JPEG' if face_image.image_data_type == IMAGE_DATA_TYPE_JPEG else 'JPEG2000'}")
            print(f"  Dimensions: {face_image.width}x{face_image.height}")
            print(f"  Size: {len(face_image.image_data)} bytes")
            print(f"  Gender: {face_image.gender.name}")
            print(f"  Expression: {face_image.expression.name}")
            print(f"  Quality: {face_image.quality}")
        
        return True
        
    except Exception as e:
        print(f"Error extracting image: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate strictly compliant ICAO 9303 DG2 files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gen_dg2_strict.py photo.jpg                    # Generate DG2 with JPEG
  python gen_dg2_strict.py photo.jpg --format jpeg2000  # Use JPEG2000 format
  python gen_dg2_strict.py photo.jpg --gender male      # Specify gender
  python gen_dg2_strict.py --extract DG2.bin            # Extract image from DG2
  python gen_dg2_strict.py --validate DG2.bin           # Validate existing DG2
        """
    )
    
    parser.add_argument('input', nargs='?', help='Input image file')
    parser.add_argument('--output', '-o', default='DG2_strict.bin', 
                       help='Output DG2 file (default: DG2_strict.bin)')
    parser.add_argument('--format', '-f', choices=['jpeg', 'jpeg2000'], 
                       default='jpeg', help='Image format (default: jpeg)')
    parser.add_argument('--gender', '-g', choices=['male', 'female', 'unspecified'],
                       default='unspecified', help='Gender (default: unspecified)')
    parser.add_argument('--quality', '-q', type=int, default=100,
                       help='Quality score 0-100 (default: 100)')
    parser.add_argument('--extract', '-e', metavar='DG2_FILE',
                       help='Extract image from DG2 file')
    parser.add_argument('--validate', '-v', metavar='DG2_FILE',
                       help='Validate existing DG2 file')
    
    args = parser.parse_args()
    
    # Handle extraction mode
    if args.extract:
        success = extract_and_save_image_from_dg2(args.extract)
        return 0 if success else 1
    
    # Handle validation mode
    if args.validate:
        with open(args.validate, 'rb') as f:
            dg2_data = f.read()
        
        is_valid, errors = validate_dg2_strict(dg2_data)
        
        print(f"DG2 Validation: {args.validate}")
        print(f"Size: {len(dg2_data)} bytes")
        print(f"Valid: {'YES' if is_valid else 'NO'}")
        
        if errors:
            print("\nValidation errors:")
            for error in errors:
                print(f"  - {error}")
        else:
            print("\nNo validation errors found.")
        
        return 0 if is_valid else 1
    
    # Generation mode - require input file
    if not args.input:
        parser.error("Input image file required for generation")
    
    # Check input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        return 1
    
    # Generate DG2
    success = generate_strict_dg2(
        args.input,
        args.output,
        args.format,
        args.gender,
        args.quality
    )
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())