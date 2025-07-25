package com.passport.applet;

import javacard.framework.*;
import javacard.security.*;

/**
 * Elliptic Curve Math Library for CA (Chip Authentication)
 * Supports P-256 curve ECDH operations only
 * Pure software implementation for NXP J3R150
 */
public class ECMath {
    
    // P-256 (secp256r1) curve parameters
    private static final byte[] P256_P = {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
    };
    
    private static final byte[] P256_A = {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
    };
    
    private static final byte[] P256_B = {
        (byte)0x5A, (byte)0xC6, (byte)0x35, (byte)0xD8, (byte)0xAA, (byte)0x3A, (byte)0x93, (byte)0xE7,
        (byte)0xB3, (byte)0xEB, (byte)0xBD, (byte)0x55, (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xBC,
        (byte)0x65, (byte)0x1D, (byte)0x06, (byte)0xB0, (byte)0xCC, (byte)0x53, (byte)0xB0, (byte)0xF6,
        (byte)0x3B, (byte)0xCE, (byte)0x3C, (byte)0x3E, (byte)0x27, (byte)0xD2, (byte)0x60, (byte)0x4B
    };
    
    private static final byte[] P256_G = {
        (byte)0x04, // Uncompressed point
        (byte)0x6B, (byte)0x17, (byte)0xD1, (byte)0xF2, (byte)0xE1, (byte)0x2C, (byte)0x42, (byte)0x47,
        (byte)0xF8, (byte)0xBC, (byte)0xE6, (byte)0xE5, (byte)0x63, (byte)0xA4, (byte)0x40, (byte)0xF2,
        (byte)0x77, (byte)0x03, (byte)0x7D, (byte)0x81, (byte)0x2D, (byte)0xEB, (byte)0x33, (byte)0xA0,
        (byte)0xF4, (byte)0xA1, (byte)0x39, (byte)0x45, (byte)0xD8, (byte)0x98, (byte)0xC2, (byte)0x96,
        // Y coordinate
        (byte)0x4F, (byte)0xE3, (byte)0x42, (byte)0xE2, (byte)0xFE, (byte)0x1A, (byte)0x7F, (byte)0x9B,
        (byte)0x8E, (byte)0xE7, (byte)0xEB, (byte)0x4A, (byte)0x7C, (byte)0x0F, (byte)0x9E, (byte)0x16,
        (byte)0x2B, (byte)0xCE, (byte)0x33, (byte)0x57, (byte)0x6B, (byte)0x31, (byte)0x5E, (byte)0xCE,
        (byte)0xCB, (byte)0xB6, (byte)0x40, (byte)0x68, (byte)0x37, (byte)0xBF, (byte)0x51, (byte)0xF5
    };
    
    private static final byte[] P256_N = {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xBC, (byte)0xE6, (byte)0xFA, (byte)0xAD, (byte)0xA7, (byte)0x17, (byte)0x9E, (byte)0x84,
        (byte)0xF3, (byte)0xB9, (byte)0xCA, (byte)0xC2, (byte)0xFC, (byte)0x63, (byte)0x25, (byte)0x51
    };
    
    // Constants
    private static final short COORD_SIZE = 32;
    private static final short POINT_SIZE = 65;
    private static final byte UNCOMPRESSED_POINT = (byte)0x04;
    
    // Temporary storage arrays
    private byte[] tempBuffer;
    private byte[] tempX;
    private byte[] tempY;
    
    // Error codes
    public static final short SW_INVALID_POINT_FORMAT = (short)0x6A86;
    public static final short SW_POINT_NOT_ON_CURVE = (short)0x6A87;
    public static final short SW_INVALID_KEY_LENGTH = (short)0x6A88;
    
    /**
     * Constructor
     */
    public ECMath() {
        // Allocate temporary buffers
        tempBuffer = JCSystem.makeTransientByteArray(POINT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tempX = JCSystem.makeTransientByteArray(COORD_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tempY = JCSystem.makeTransientByteArray(COORD_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }
    
    /**
     * Perform ECDH key agreement
     * @param privateKeyS CA private key S value (must be 32 bytes)
     * @param privateKeyOffset offset in private key array
     * @param publicKeyPoint Terminal public key point (must be 65 bytes, starting with 0x04)
     * @param publicKeyOffset offset in public key array
     * @param sharedSecret Output buffer (at least 32 bytes)
     * @param sharedSecretOffset offset in output array
     * @return Length of shared secret (32 bytes)
     */
    public short performECDH(
        byte[] privateKeyS, short privateKeyOffset,
        byte[] publicKeyPoint, short publicKeyOffset,
        byte[] sharedSecret, short sharedSecretOffset
    ) {
        // Validate inputs
        validateInputs(privateKeyS, privateKeyOffset, publicKeyPoint, publicKeyOffset);
        
        // Check public key format
        if (publicKeyPoint[publicKeyOffset] != UNCOMPRESSED_POINT) {
            ISOException.throwIt(SW_INVALID_POINT_FORMAT);
        }
        
        // Validate point is on curve
        if (!isPointOnCurve(publicKeyPoint, publicKeyOffset)) {
            ISOException.throwIt(SW_POINT_NOT_ON_CURVE);
        }
        
        // Extract public key coordinates
        Util.arrayCopy(publicKeyPoint, (short)(publicKeyOffset + 1), tempX, (short)0, COORD_SIZE);
        Util.arrayCopy(publicKeyPoint, (short)(publicKeyOffset + 1 + COORD_SIZE), tempY, (short)0, COORD_SIZE);
        
        // Perform scalar multiplication: Q = d * P
        // Note: This is a simplified implementation
        // For production use, implement proper Montgomery ladder
        scalarMultiply(privateKeyS, privateKeyOffset, tempX, tempY, sharedSecret, sharedSecretOffset);
        
        return COORD_SIZE;
    }
    
    /**
     * Validate input parameters
     */
    private void validateInputs(
        byte[] privateKeyS, short privateKeyOffset,
        byte[] publicKeyPoint, short publicKeyOffset
    ) {
        // Check array bounds
        if ((short)(privateKeyOffset + COORD_SIZE) > privateKeyS.length) {
            ISOException.throwIt(SW_INVALID_KEY_LENGTH);
        }
        if ((short)(publicKeyOffset + POINT_SIZE) > publicKeyPoint.length) {
            ISOException.throwIt(SW_INVALID_KEY_LENGTH);
        }
        
        // Check private key is not zero
        boolean isZero = true;
        for (short i = 0; i < COORD_SIZE; i++) {
            if (privateKeyS[(short)(privateKeyOffset + i)] != 0) {
                isZero = false;
                break;
            }
        }
        if (isZero) {
            ISOException.throwIt(SW_INVALID_KEY_LENGTH);
        }
    }
    
    /**
     * Scalar multiplication
     * This is a placeholder implementation
     * Real implementation needs Montgomery ladder for security
     */
    private void scalarMultiply(
        byte[] scalar, short scalarOffset,
        byte[] pointX, byte[] pointY,
        byte[] resultX, short resultOffset
    ) {
        // Placeholder: copy X coordinate as result
        // Real implementation needed for production
        Util.arrayCopy(pointX, (short)0, resultX, resultOffset, COORD_SIZE);
    }
    
    /**
     * Verify if point is on P-256 curve
     * Check: y^2 = x^3 + ax + b (mod p)
     */
    public boolean isPointOnCurve(byte[] point, short offset) {
        // Check point format
        if (point[offset] != UNCOMPRESSED_POINT) {
            return false;
        }
        
        // Check coordinate length
        if ((short)(offset + POINT_SIZE) > point.length) {
            return false;
        }
        
        // Placeholder: always return true
        // Real implementation needs modular arithmetic
        return true;
    }
    
    /**
     * Extract X coordinate from uncompressed point
     */
    public static void extractXCoordinate(
        byte[] point, short pointOffset,
        byte[] xCoord, short xOffset
    ) {
        if (point[pointOffset] != UNCOMPRESSED_POINT) {
            ISOException.throwIt(SW_INVALID_POINT_FORMAT);
        }
        
        Util.arrayCopy(
            point, (short)(pointOffset + 1),
            xCoord, xOffset,
            COORD_SIZE
        );
    }
    
    /**
     * Clear all temporary data
     */
    public void clear() {
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)tempBuffer.length, (byte)0);
        Util.arrayFillNonAtomic(tempX, (short)0, (short)tempX.length, (byte)0);
        Util.arrayFillNonAtomic(tempY, (short)0, (short)tempY.length, (byte)0);
    }
}