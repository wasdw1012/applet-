/**
 * DG2 Validator - Strict Implementation
 * Based on BSI TR-03110 and ISO/IEC 19794-5 standards
 * 
 * This validator implements the most strict validation rules
 * as found in German eID verification systems.
 */

#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>

namespace DG2Validator {

// ASN.1 Tag definitions
constexpr uint8_t TAG_DG2 = 0x75;
constexpr uint8_t TAG_BIOMETRIC_INFO_GROUP = 0x7F;
constexpr uint8_t TAG_BIOMETRIC_INFO_GROUP_2 = 0x61;
constexpr uint8_t TAG_INSTANCE_NUMBER = 0x02;
constexpr uint8_t TAG_BIOMETRIC_INFO_TEMPLATE = 0x7F;
constexpr uint8_t TAG_BIOMETRIC_INFO_TEMPLATE_2 = 0x60;
constexpr uint8_t TAG_CBEFF_HEADER = 0xA1;
constexpr uint8_t TAG_BIOMETRIC_DATA = 0x5F;
constexpr uint8_t TAG_BIOMETRIC_DATA_2 = 0x2E;

// CBEFF Header tags
constexpr uint8_t TAG_PATRON_VERSION = 0x80;
constexpr uint8_t TAG_BIOMETRIC_TYPE = 0x81;
constexpr uint8_t TAG_BIOMETRIC_SUBTYPE = 0x82;
constexpr uint8_t TAG_CREATION_DATE = 0x83;
constexpr uint8_t TAG_VALIDITY_PERIOD = 0x85;
constexpr uint8_t TAG_CREATOR = 0x86;
constexpr uint8_t TAG_FORMAT_OWNER = 0x87;
constexpr uint8_t TAG_FORMAT_TYPE = 0x88;

// Expected values
constexpr uint8_t BIOMETRIC_TYPE_FACE = 0x02;
constexpr uint16_t FORMAT_OWNER_ICAO = 0x0101;
constexpr uint16_t FORMAT_TYPE_FACE = 0x0008;

// ISO 19794-5 constants
constexpr uint8_t FACE_IMAGE_TYPE_FULL_FRONTAL = 0x01;
constexpr uint8_t IMAGE_TYPE_JPEG2000 = 0x02;

class StrictDG2Validator {
private:
    const uint8_t* data;
    size_t dataLen;
    size_t pos;
    
    struct ValidationResult {
        bool valid;
        std::string error;
        size_t imageOffset;
        size_t imageLength;
        uint16_t imageWidth;
        uint16_t imageHeight;
    };

public:
    StrictDG2Validator(const uint8_t* dg2Data, size_t len) 
        : data(dg2Data), dataLen(len), pos(0) {}
    
    ValidationResult validate() {
        ValidationResult result = {false, "", 0, 0, 0, 0};
        
        try {
            // 1. Validate DG2 tag
            validateTag(TAG_DG2, "DG2");
            
            // 2. Validate Biometric Info Group Template (7F61)
            validateCompositeTag(TAG_BIOMETRIC_INFO_GROUP, TAG_BIOMETRIC_INFO_GROUP_2, 
                               "Biometric Info Group");
            
            // 3. Validate Instance Number (must be 01)
            validateTag(TAG_INSTANCE_NUMBER, "Instance Number");
            size_t instanceLen = parseLength();
            if (instanceLen != 1 || data[pos] != 0x01) {
                throw std::runtime_error("Instance number must be 01");
            }
            pos += instanceLen;
            
            // 4. Validate Biometric Info Template (7F60)
            validateCompositeTag(TAG_BIOMETRIC_INFO_TEMPLATE, TAG_BIOMETRIC_INFO_TEMPLATE_2,
                               "Biometric Info Template");
            
            // 5. Validate CBEFF Header (A1)
            validateTag(TAG_CBEFF_HEADER, "CBEFF Header");
            size_t cbeffLen = parseLength();
            size_t cbeffEnd = pos + cbeffLen;
            
            // Parse CBEFF Header strictly
            validateCBEFFHeader(cbeffEnd);
            
            // 6. Validate Biometric Data Block (5F2E)
            validateCompositeTag(TAG_BIOMETRIC_DATA, TAG_BIOMETRIC_DATA_2,
                               "Biometric Data Block");
            size_t bioDataLen = parseLength();
            size_t bioDataStart = pos;
            
            // 7. Parse ISO 19794-5 Facial Record
            validateISO19794Record(bioDataLen, result);
            
            result.valid = true;
            
        } catch (const std::exception& e) {
            result.error = e.what();
            result.valid = false;
        }
        
        return result;
    }
    
private:
    void validateTag(uint8_t expectedTag, const std::string& name) {
        if (pos >= dataLen) {
            throw std::runtime_error("Unexpected end of data while reading " + name);
        }
        
        if (data[pos] != expectedTag) {
            std::stringstream ss;
            ss << "Expected " << name << " tag 0x" << std::hex 
               << (int)expectedTag << " but got 0x" << (int)data[pos];
            throw std::runtime_error(ss.str());
        }
        pos++;
    }
    
    void validateCompositeTag(uint8_t tag1, uint8_t tag2, const std::string& name) {
        if (pos + 1 >= dataLen) {
            throw std::runtime_error("Unexpected end of data while reading " + name);
        }
        
        if (data[pos] != tag1 || data[pos + 1] != tag2) {
            std::stringstream ss;
            ss << "Expected " << name << " tag 0x" << std::hex 
               << (int)tag1 << std::hex << (int)tag2 
               << " but got 0x" << (int)data[pos] << (int)data[pos + 1];
            throw std::runtime_error(ss.str());
        }
        pos += 2;
    }
    
    size_t parseLength() {
        if (pos >= dataLen) {
            throw std::runtime_error("Unexpected end of data while parsing length");
        }
        
        if (data[pos] < 0x80) {
            // Short form
            return data[pos++];
        } else {
            // Long form
            int numOctets = data[pos] & 0x7F;
            pos++;
            
            if (numOctets == 0 || numOctets > 4) {
                throw std::runtime_error("Invalid length encoding");
            }
            
            if (pos + numOctets > dataLen) {
                throw std::runtime_error("Unexpected end of data in length");
            }
            
            size_t length = 0;
            for (int i = 0; i < numOctets; i++) {
                length = (length << 8) | data[pos++];
            }
            
            return length;
        }
    }
    
    void validateCBEFFHeader(size_t endPos) {
        bool hasPatronVersion = false;
        bool hasBiometricType = false;
        bool hasFormatOwner = false;
        bool hasFormatType = false;
        
        while (pos < endPos) {
            uint8_t tag = data[pos++];
            size_t len = parseLength();
            
            switch (tag) {
                case TAG_PATRON_VERSION:
                    if (len != 2 || data[pos] != 0x01 || data[pos + 1] != 0x01) {
                        throw std::runtime_error("Invalid patron version (must be 0x0101)");
                    }
                    hasPatronVersion = true;
                    break;
                    
                case TAG_BIOMETRIC_TYPE:
                    if (len != 1 || data[pos] != BIOMETRIC_TYPE_FACE) {
                        throw std::runtime_error("Invalid biometric type (must be Face)");
                    }
                    hasBiometricType = true;
                    break;
                    
                case TAG_FORMAT_OWNER:
                    if (len != 2) {
                        throw std::runtime_error("Invalid format owner length");
                    }
                    uint16_t owner = (data[pos] << 8) | data[pos + 1];
                    if (owner != FORMAT_OWNER_ICAO) {
                        throw std::runtime_error("Invalid format owner (must be ICAO)");
                    }
                    hasFormatOwner = true;
                    break;
                    
                case TAG_FORMAT_TYPE:
                    if (len != 2) {
                        throw std::runtime_error("Invalid format type length");
                    }
                    uint16_t type = (data[pos] << 8) | data[pos + 1];
                    if (type != FORMAT_TYPE_FACE) {
                        throw std::runtime_error("Invalid format type");
                    }
                    hasFormatType = true;
                    break;
            }
            
            pos += len;
        }
        
        // Verify all mandatory fields are present
        if (!hasPatronVersion || !hasBiometricType || !hasFormatOwner || !hasFormatType) {
            throw std::runtime_error("Missing mandatory CBEFF header fields");
        }
    }
    
    void validateISO19794Record(size_t recordLen, ValidationResult& result) {
        size_t recordStart = pos;
        
        // 1. Format Identifier (FAC\0)
        if (pos + 4 > dataLen || memcmp(&data[pos], "FAC\x00", 4) != 0) {
            throw std::runtime_error("Invalid ISO 19794-5 format identifier");
        }
        pos += 4;
        
        // 2. Version Number (010\0)
        if (pos + 4 > dataLen || memcmp(&data[pos], "010\x00", 4) != 0) {
            throw std::runtime_error("Invalid ISO 19794-5 version");
        }
        pos += 4;
        
        // 3. Record Length
        if (pos + 4 > dataLen) {
            throw std::runtime_error("Unexpected end of data reading record length");
        }
        uint32_t declaredLen = (data[pos] << 24) | (data[pos+1] << 16) | 
                               (data[pos+2] << 8) | data[pos+3];
        pos += 4;
        
        if (declaredLen != recordLen) {
            throw std::runtime_error("ISO record length mismatch");
        }
        
        // 4. Number of Images (must be 1)
        if (pos + 2 > dataLen) {
            throw std::runtime_error("Unexpected end of data reading image count");
        }
        uint16_t numImages = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        
        if (numImages != 1) {
            throw std::runtime_error("Only single image is allowed in DG2");
        }
        
        // 5. Facial Information Block
        parseFacialInformation();
        
        // 6. Image Information Block
        parseImageInformation(result);
        
        // 7. Image Data
        size_t headerSize = pos - recordStart;
        result.imageOffset = pos;
        result.imageLength = recordLen - headerSize;
        
        // Validate JPEG2000 signature
        validateJPEG2000Signature();
    }
    
    void parseFacialInformation() {
        // Number of feature points
        if (pos + 2 > dataLen) {
            throw std::runtime_error("Unexpected end reading feature points");
        }
        uint16_t numFeatures = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        
        // Gender, Eye Color, Hair Color (3 bytes)
        if (pos + 3 > dataLen) {
            throw std::runtime_error("Unexpected end reading facial attributes");
        }
        pos += 3;
        
        // Feature mask (3 bytes)
        if (pos + 3 > dataLen) {
            throw std::runtime_error("Unexpected end reading feature mask");
        }
        pos += 3;
        
        // Expression (2 bytes)
        if (pos + 2 > dataLen) {
            throw std::runtime_error("Unexpected end reading expression");
        }
        pos += 2;
        
        // Pose angles (3 bytes)
        if (pos + 3 > dataLen) {
            throw std::runtime_error("Unexpected end reading pose angles");
        }
        pos += 3;
        
        // Pose angle uncertainty (3 bytes)
        if (pos + 3 > dataLen) {
            throw std::runtime_error("Unexpected end reading pose uncertainty");
        }
        pos += 3;
        
        // Skip feature points
        pos += numFeatures * 8;
    }
    
    void parseImageInformation(ValidationResult& result) {
        // Face image type
        if (pos >= dataLen) {
            throw std::runtime_error("Unexpected end reading face image type");
        }
        uint8_t faceType = data[pos++];
        if (faceType != FACE_IMAGE_TYPE_FULL_FRONTAL) {
            throw std::runtime_error("Only full frontal face images are allowed");
        }
        
        // Image data type
        if (pos >= dataLen) {
            throw std::runtime_error("Unexpected end reading image data type");
        }
        uint8_t imageType = data[pos++];
        if (imageType != IMAGE_TYPE_JPEG2000) {
            throw std::runtime_error("Only JPEG2000 images are allowed");
        }
        
        // Width and Height
        if (pos + 4 > dataLen) {
            throw std::runtime_error("Unexpected end reading image dimensions");
        }
        result.imageWidth = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        result.imageHeight = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        
        // Validate dimensions
        if (result.imageWidth < 240 || result.imageWidth > 1024 ||
            result.imageHeight < 320 || result.imageHeight > 1024) {
            throw std::runtime_error("Image dimensions out of allowed range");
        }
        
        // Skip remaining image info fields (color space, source type, etc.)
        if (pos + 4 > dataLen) {
            throw std::runtime_error("Unexpected end reading image info");
        }
        pos += 4;
    }
    
    void validateJPEG2000Signature() {
        // JPEG2000 signature: 0x0000000C6A502020
        const uint8_t jp2Sig[] = {0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20};
        
        bool foundSig = false;
        // Check first 20 bytes for signature
        for (size_t i = pos; i < pos + 20 && i + 8 <= dataLen; i++) {
            if (memcmp(&data[i], jp2Sig, 8) == 0) {
                foundSig = true;
                break;
            }
        }
        
        if (!foundSig) {
            throw std::runtime_error("Invalid JPEG2000 signature");
        }
    }
};

} // namespace DG2Validator

// Test function
void testDG2Validation(const uint8_t* dg2Data, size_t len) {
    DG2Validator::StrictDG2Validator validator(dg2Data, len);
    auto result = validator.validate();
    
    if (result.valid) {
        std::cout << "DG2 validation PASSED" << std::endl;
        std::cout << "Image dimensions: " << result.imageWidth 
                  << "x" << result.imageHeight << std::endl;
        std::cout << "Image data at offset: " << result.imageOffset 
                  << ", length: " << result.imageLength << std::endl;
    } else {
        std::cout << "DG2 validation FAILED: " << result.error << std::endl;
    }
}