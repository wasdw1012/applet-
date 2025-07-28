package com.deepsea.passport;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Elliptic Curve Math Library for CA (Chip Authentication)
 * Complete software implementation of P-256 ECDH
 * Extracted and simplified from jcmathlib
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
    
    // P-256 base point G (uncompressed format)
    private static final byte[] P256_G = {
        (byte)0x04,  // Uncompressed point indicator
        // X coordinate
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
    
    // Constants
    private static final short COORD_SIZE = 32;
    private static final short BIGNAT_SIZE = 33; // Extra byte for operations
    private static final short POINT_SIZE = 65;
    private static final byte UNCOMPRESSED_POINT = (byte)0x04;
    
    // RSA engine for modular operations (using RSA trick from jcmathlib)
    private static final short RSA_KEY_SIZE = 512; // bits
    private static final short RSA_BLOCK_SIZE = 64; // bytes
    private RSAPublicKey rsaPubKey;
    private RSAPrivateKey rsaPrivKey;
    private Cipher rsaCipher;
    
    // Temporary Bignat storage
    private byte[] tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
    private byte[] modP; // Store P256_P in proper size
    
    // EC Point storage
    private byte[] pointX1, pointY1;
    private byte[] pointX2, pointY2; 
    private byte[] pointX3, pointY3;
    
    // Temporary arrays for RSA operations
    private byte[] rsaBuffer;
    
    // Additional temporary buffers to avoid dynamic allocation in methods
    private byte[] tempFull1;  // For pointDouble/pointAdd x1Full
    private byte[] tempFull2;  // For pointDouble/pointAdd y1Full
    private byte[] tempFull3;  // For pointAdd x2Full
    private byte[] tempFull4;  // For pointAdd y2Full
    
    // Error codes
    public static final short SW_INVALID_POINT_FORMAT = (short)0x6A86;
    public static final short SW_INVALID_KEY_LENGTH = (short)0x6A88;
    
    /**
     * Constructor
     */
    public ECMath() {
        // Allocate Bignat buffers
        tmp1 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tmp2 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tmp3 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tmp4 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tmp5 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tmp6 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        // Prepare modulus P in RSA size
        modP = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        prependZeros(P256_P, (short)0, COORD_SIZE, modP, (short)0, RSA_BLOCK_SIZE);
        
        // EC point storage  
        pointX1 = JCSystem.makeTransientByteArray(BIGNAT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pointY1 = JCSystem.makeTransientByteArray(BIGNAT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pointX2 = JCSystem.makeTransientByteArray(BIGNAT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pointY2 = JCSystem.makeTransientByteArray(BIGNAT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pointX3 = JCSystem.makeTransientByteArray(BIGNAT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pointY3 = JCSystem.makeTransientByteArray(BIGNAT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        rsaBuffer = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        // Initialize additional temporary buffers
        tempFull1 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tempFull2 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tempFull3 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tempFull4 = JCSystem.makeTransientByteArray(RSA_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        // Initialize RSA engine for modular arithmetic
        try {
            rsaPubKey = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, RSA_KEY_SIZE, false);
            rsaPrivKey = (RSAPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PRIVATE, RSA_KEY_SIZE, false);
            rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            
            // Set a large modulus (all FFs) for general use
            Util.arrayFillNonAtomic(rsaBuffer, (short)0, RSA_BLOCK_SIZE, (byte)0xFF);
            rsaBuffer[0] = (byte)0x7F; // Make sure it's positive
            rsaPubKey.setModulus(rsaBuffer, (short)0, RSA_BLOCK_SIZE);
            rsaPrivKey.setModulus(rsaBuffer, (short)0, RSA_BLOCK_SIZE);
            
        } catch (Exception e) {
            // RSA not available - fallback to basic operations
            rsaCipher = null;
        }
    }
    
    /**
     * Perform ECDH key agreement
     */
    public short performECDH(
        byte[] privateKeyS, short privateKeyOffset,
        byte[] publicKeyPoint, short publicKeyOffset,  
        byte[] sharedSecret, short sharedSecretOffset
    ) {
        // Parameter validation
        if (privateKeyS == null || publicKeyPoint == null || sharedSecret == null) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        
        // Verify public key format (must be uncompressed)
        if (publicKeyPoint[publicKeyOffset] != UNCOMPRESSED_POINT) {
            ISOException.throwIt(SW_INVALID_POINT_FORMAT);
        }
        
        // Validate inputs
        if ((short)(privateKeyOffset + COORD_SIZE) > privateKeyS.length ||
            (short)(publicKeyOffset + POINT_SIZE) > publicKeyPoint.length) {
            ISOException.throwIt(SW_INVALID_KEY_LENGTH);
        }
        
        if (publicKeyPoint[publicKeyOffset] != UNCOMPRESSED_POINT) {
            ISOException.throwIt(SW_INVALID_POINT_FORMAT);
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
        
        // Extract public key coordinates
        Util.arrayCopy(publicKeyPoint, (short)(publicKeyOffset + 1), 
                      pointX1, (short)1, COORD_SIZE);
        Util.arrayCopy(publicKeyPoint, (short)(publicKeyOffset + 1 + COORD_SIZE), 
                      pointY1, (short)1, COORD_SIZE);
        pointX1[0] = 0;
        pointY1[0] = 0;
        
        // Validate that the point is on the curve
        if (!isPointOnCurve(pointX1, pointY1)) {
            ISOException.throwIt(SW_INVALID_POINT_FORMAT);
        }
        
        // Perform scalar multiplication
        scalarMultiply(privateKeyS, privateKeyOffset, pointX1, pointY1, pointX3, pointY3);
        
        // Return X coordinate as shared secret
        Util.arrayCopy(pointX3, (short)1, sharedSecret, sharedSecretOffset, COORD_SIZE);
        
        return COORD_SIZE;
    }
    
    /**
     * Scalar multiplication using double-and-add
     */
    private void scalarMultiply(
        byte[] scalar, short scalarOffset,
        byte[] pointX, byte[] pointY,
        byte[] resultX, byte[] resultY
    ) {
        // Initialize result to infinity (all zeros)
        Util.arrayFillNonAtomic(resultX, (short)0, BIGNAT_SIZE, (byte)0);
        Util.arrayFillNonAtomic(resultY, (short)0, BIGNAT_SIZE, (byte)0);
        
        // Copy base point
        Util.arrayCopy(pointX, (short)0, pointX2, (short)0, BIGNAT_SIZE);
        Util.arrayCopy(pointY, (short)0, pointY2, (short)0, BIGNAT_SIZE);
        
        boolean firstBit = true;
        
        // Process scalar bits from MSB to LSB
        for (short i = 0; i < COORD_SIZE; i++) {
            byte b = scalar[(short)(scalarOffset + i)];
            
            for (short j = 7; j >= 0; j--) {
                if (!firstBit) {
                    // Double result point
                    pointDouble(resultX, resultY, resultX, resultY);
                }
                
                if ((b & (byte)(1 << j)) != 0) {
                    if (firstBit) {
                        // First bit - copy base point
                        copyPoint(pointX2, resultX);
                        copyPoint(pointY2, resultY);
                        firstBit = false;
                    } else {
                        // Add base point
                        pointAdd(resultX, resultY, pointX2, pointY2, resultX, resultY);
                    }
                }
            }
        }
    }
    
    /**
     * Point doubling: R = 2P
     * For P-256: lambda = (3*x^2 + a) / (2*y)
     */
    private void pointDouble(
        byte[] x1, byte[] y1,
        byte[] x3, byte[] y3
    ) {
        // Check for point at infinity
        if (isPointZero(x1) && isPointZero(y1)) {
            copyPoint(x1, x3);
            copyPoint(y1, y3);
            return;
        }
        
        // Convert point coordinates to RSA_BLOCK_SIZE for modular operations
        // Use pre-allocated buffers instead of dynamic allocation
        prependZeros(x1, (short)0, BIGNAT_SIZE, tempFull1, (short)0, RSA_BLOCK_SIZE);
        prependZeros(y1, (short)0, BIGNAT_SIZE, tempFull2, (short)0, RSA_BLOCK_SIZE);
        
        // tmp1 = x1^2
        modSquare(tempFull1, tmp1);
        
        // tmp2 = 3 * x1^2
        copyBignat(tmp1, tmp2);
        modAdd(tmp2, tmp1, tmp2);
        modAdd(tmp2, tmp1, tmp2);
        
        // tmp2 = 3*x1^2 + a (where a = P256_A = p-3)
        // Use tempFull3 for aValue instead of dynamic allocation
        prependZeros(P256_A, (short)0, COORD_SIZE, tempFull3, (short)0, RSA_BLOCK_SIZE);
        modAdd(tmp2, tempFull3, tmp2);
        
        // tmp3 = 2*y1
        modAdd(tempFull2, tempFull2, tmp3);
        
        // tmp4 = tmp2 / tmp3 = lambda
        modDiv(tmp2, tmp3, tmp4);
        
        // x3 = lambda^2 - 2*x1
        modSquare(tmp4, tmp5);
        modAdd(x1Full, x1Full, tmp3);
        modSub(tmp5, tmp3, tmp5);
        
        // y3 = lambda*(x1 - x3) - y1
        modSub(x1Full, tmp5, tmp6);
        modMul(tmp4, tmp6, tmp3);
        modSub(tmp3, y1Full, tmp6);
        
        // Copy results back to 33-byte format
        Util.arrayCopy(tmp5, (short)(RSA_BLOCK_SIZE - BIGNAT_SIZE), x3, (short)0, BIGNAT_SIZE);
        Util.arrayCopy(tmp6, (short)(RSA_BLOCK_SIZE - BIGNAT_SIZE), y3, (short)0, BIGNAT_SIZE);
    }

    /**
     * Point addition: R = P + Q
     */
    private void pointAdd(
        byte[] x1, byte[] y1,
        byte[] x2, byte[] y2,
        byte[] x3, byte[] y3
    ) {
        // Check if same point
        if (isPointEqual(x1, y1, x2, y2)) {
            pointDouble(x1, y1, x3, y3);
            return;
        }
        
        // Check for point at infinity
        if (isPointZero(x1) && isPointZero(y1)) {
            copyPoint(x2, x3);
            copyPoint(y2, y3);
            return;
        }
        if (isPointZero(x2) && isPointZero(y2)) {
            copyPoint(x1, x3);
            copyPoint(y1, y3);
            return;
        }
        
        // Convert to full size
        // Use pre-allocated buffers instead of dynamic allocation
        prependZeros(x1, (short)0, BIGNAT_SIZE, tempFull1, (short)0, RSA_BLOCK_SIZE);
        prependZeros(y1, (short)0, BIGNAT_SIZE, tempFull2, (short)0, RSA_BLOCK_SIZE);
        prependZeros(x2, (short)0, BIGNAT_SIZE, tempFull3, (short)0, RSA_BLOCK_SIZE);
        prependZeros(y2, (short)0, BIGNAT_SIZE, tempFull4, (short)0, RSA_BLOCK_SIZE);
        
        // lambda = (y2 - y1) / (x2 - x1)
        modSub(tempFull4, tempFull2, tmp1);
        modSub(tempFull3, tempFull1, tmp2);
        modDiv(tmp1, tmp2, tmp3);
        
        // x3 = lambda^2 - x1 - x2
        modSquare(tmp3, tmp4);
        modSub(tmp4, tempFull1, tmp5);
        modSub(tmp5, tempFull3, tmp5);
        
        // y3 = lambda*(x1 - x3) - y1
        modSub(tempFull1, tmp5, tmp4);
        modMul(tmp3, tmp4, tmp6);
        modSub(tmp6, tempFull2, tmp6);
        
        // Copy results back
        Util.arrayCopy(tmp5, (short)(RSA_BLOCK_SIZE - BIGNAT_SIZE), x3, (short)0, BIGNAT_SIZE);
        Util.arrayCopy(tmp6, (short)(RSA_BLOCK_SIZE - BIGNAT_SIZE), y3, (short)0, BIGNAT_SIZE);
    }
    
    /**
     * Modular multiplication using RSA trick
     * result = (a * b) mod P256_P
     */
    private void modMul(byte[] a, byte[] b, byte[] result) {
        if (rsaCipher != null) {
            // Use RSA trick for fast multiplication
            rsaTrickMultiply(a, b, result);
            // Result is already reduced modulo P
        } else {
            // Fallback to basic multiplication
            basicModMul(a, b, result);
        }
    }
    
    /**
     * RSA trick multiplication
     */
    private void rsaTrickMultiply(byte[] a, byte[] b, byte[] result) {
        // Set RSA public exponent to 2 (using (x+y)^2 method from jcmathlib)
        rsaPubKey.setExponent(new byte[]{2}, (short)0, (short)1);
        rsaPubKey.setModulus(modP, (short)0, RSA_BLOCK_SIZE);
        
        rsaCipher.init(rsaPubKey, Cipher.MODE_ENCRYPT);
        
        // Compute (a+b)
        modAdd(a, b, tmp1);
        
        // Compute (a+b)^2
        rsaCipher.doFinal(tmp1, (short)0, RSA_BLOCK_SIZE, tmp2, (short)0);
        
        // Compute a^2
        rsaCipher.doFinal(a, (short)0, RSA_BLOCK_SIZE, tmp3, (short)0);
        
        // Compute b^2
        rsaCipher.doFinal(b, (short)0, RSA_BLOCK_SIZE, tmp4, (short)0);
        
        // (a+b)^2 - a^2 - b^2 = 2ab
        modSub(tmp2, tmp3, tmp5);
        modSub(tmp5, tmp4, tmp5);
        
        // Divide by 2: simple right shift since 2ab < 2p
        // If LSB is 1, add p first to make it even
        if ((tmp5[RSA_BLOCK_SIZE - 1] & 1) != 0) {
            add(tmp5, modP, tmp5);
        }
        
        // Right shift by 1
        short carry = 0;
        for (short i = 0; i < RSA_BLOCK_SIZE; i++) {
            short current = (short)((tmp5[i] & 0xFF) | (carry << 8));
            result[i] = (byte)(current >> 1);
            carry = (short)((current & 1) << 7);
        }
    }
    
    /**
     * Basic modular multiplication (slow but works)
     */
    private void basicModMul(byte[] a, byte[] b, byte[] result) {
        // Simple shift-and-add multiplication
        Util.arrayFillNonAtomic(result, (short)0, RSA_BLOCK_SIZE, (byte)0);
        copyBignat(a, tmp3);
        
        for (short i = (short)(RSA_BLOCK_SIZE - 1); i >= 0; i--) {
            byte currentByte = b[i];
            for (short bit = 0; bit < 8; bit++) {
                if ((currentByte & 1) != 0) {
                    modAdd(result, tmp3, result);
                }
                currentByte >>= 1;
                // Double tmp3
                modAdd(tmp3, tmp3, tmp3);
            }
        }
    }
    
    /**
     * Modular square
     */
    private void modSquare(byte[] a, byte[] result) {
        if (rsaCipher != null) {
            // Use RSA with exponent 2
            rsaPubKey.setExponent(new byte[]{2}, (short)0, (short)1);
            rsaPubKey.setModulus(modP, (short)0, RSA_BLOCK_SIZE);
            rsaCipher.init(rsaPubKey, Cipher.MODE_ENCRYPT);
            short len = rsaCipher.doFinal(a, (short)0, RSA_BLOCK_SIZE, result, (short)0);
            // Pad result if needed
            if (len < RSA_BLOCK_SIZE) {
                Util.arrayCopyNonAtomic(result, (short)0, tmp3, (short)(RSA_BLOCK_SIZE - len), len);
                Util.arrayFillNonAtomic(tmp3, (short)0, (short)(RSA_BLOCK_SIZE - len), (byte)0);
                Util.arrayCopyNonAtomic(tmp3, (short)0, result, (short)0, RSA_BLOCK_SIZE);
            }
        } else {
            modMul(a, a, result);
        }
    }
    
    /**
     * Modular addition
     */
    private void modAdd(byte[] a, byte[] b, byte[] result) {
        short carry = 0;
        
        // Add from LSB to MSB
        for (short i = (short)(RSA_BLOCK_SIZE - 1); i >= 0; i--) {
            short sum = (short)((a[i] & 0xFF) + (b[i] & 0xFF) + carry);
            result[i] = (byte)sum;
            carry = (short)(sum >> 8);
        }
        
        // Reduce if needed
        if (carry != 0 || compare(result, modP) >= 0) {
            subtract(result, modP, result);
        }
    }
    
    /**
     * Modular subtraction
     */
    private void modSub(byte[] a, byte[] b, byte[] result) {
        if (compare(a, b) < 0) {
            // a < b, compute (a + p) - b
            add(a, modP, result);
            subtract(result, b, result);
        } else {
            subtract(a, b, result);
        }
    }
    
    /**
     * Modular division: result = a / b mod p
     * Computed as: a * b^(-1) mod p
     */
    private void modDiv(byte[] a, byte[] b, byte[] result) {
        // Compute b^(-1) mod p using Fermat's little theorem:
        // b^(-1) = b^(p-2) mod p
        
        // First compute p-2
        copyBignat(modP, tmp5);
        // Subtract 2 with proper borrow handling
        short borrow = 2;
        for (short i = (short)(RSA_BLOCK_SIZE - 1); i >= 0 && borrow > 0; i--) {
            short val = (short)((tmp5[i] & 0xFF) - borrow);
            if (val < 0) {
                val += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            tmp5[i] = (byte)val;
        }
        
        // Compute b^(p-2) mod p
        modExp(b, tmp5, tmp6);
        
        // result = a * b^(-1) mod p
        modMul(a, tmp6, result);
    }
    
    /**
     * Modular exponentiation using RSA engine
     */
    private void modExp(byte[] base, byte[] exp, byte[] result) {
        if (rsaCipher == null) {
            // No RSA - use repeated multiplication (very slow!)
            copyBignat(base, result);
            copyBignat(base, tmp4);
            
            // Skip first bit
            boolean first = true;
            for (short i = 0; i < RSA_BLOCK_SIZE; i++) {
                byte e = exp[i];
                for (short j = 7; j >= 0; j--) {
                    if (!first) {
                        modSquare(result, result);
                    }
                    if ((e & (byte)(1 << j)) != 0 && !first) {
                        modMul(result, tmp4, result);
                    }
                    first = false;
                }
            }
            return;
        }
        
        // Use RSA engine with custom exponent
        short expLen = RSA_BLOCK_SIZE;
        short expStart = 0;
        
        // Find first non-zero byte
        while (expStart < RSA_BLOCK_SIZE && exp[expStart] == 0) {
            expStart++;
        }
        
        if (expStart == RSA_BLOCK_SIZE) {
            // Exponent is zero - result is 1
            Util.arrayFillNonAtomic(result, (short)0, RSA_BLOCK_SIZE, (byte)0);
            result[RSA_BLOCK_SIZE - 1] = 1;
            return;
        }
        
        expLen = (short)(RSA_BLOCK_SIZE - expStart);
        
        rsaPubKey.setExponent(exp, expStart, expLen);
        rsaPubKey.setModulus(modP, (short)0, RSA_BLOCK_SIZE);
        rsaCipher.init(rsaPubKey, Cipher.MODE_ENCRYPT);
        
        short len = rsaCipher.doFinal(base, (short)0, RSA_BLOCK_SIZE, result, (short)0);
        
        // Pad result if needed
        if (len < RSA_BLOCK_SIZE) {
            Util.arrayCopyNonAtomic(result, (short)0, tmp6, (short)(RSA_BLOCK_SIZE - len), len);
            Util.arrayFillNonAtomic(tmp6, (short)0, (short)(RSA_BLOCK_SIZE - len), (byte)0);
            Util.arrayCopyNonAtomic(tmp6, (short)0, result, (short)0, RSA_BLOCK_SIZE);
        }
    }
    
    /**
     * Reduce value modulo P256_P
     */
    private void mod(byte[] value, byte[] result) {
        copyBignat(value, result);
        while (compare(result, modP) >= 0) {
            subtract(result, modP, result);
        }
    }
    
    /**
     * Basic addition with carry
     */
    private short add(byte[] a, byte[] b, byte[] result) {
        short carry = 0;
        for (short i = (short)(RSA_BLOCK_SIZE - 1); i >= 0; i--) {
            short sum = (short)((a[i] & 0xFF) + (b[i] & 0xFF) + carry);
            result[i] = (byte)sum;
            carry = (short)(sum >> 8);
        }
        return carry;
    }
    
    /**
     * Basic subtraction with borrow
     */
    private short subtract(byte[] a, byte[] b, byte[] result) {
        short borrow = 0;
        for (short i = (short)(RSA_BLOCK_SIZE - 1); i >= 0; i--) {
            short diff = (short)((a[i] & 0xFF) - (b[i] & 0xFF) - borrow);
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = (byte)diff;
        }
        return borrow;
    }
    
    /**
     * Compare two bignats
     */
    private byte compare(byte[] a, byte[] b) {
        for (short i = 0; i < RSA_BLOCK_SIZE; i++) {
            short aVal = (short)(a[i] & 0xFF);
            short bVal = (short)(b[i] & 0xFF);
            if (aVal > bVal) return 1;
            if (aVal < bVal) return -1;
        }
        return 0;
    }
    
    /**
     * Utility functions
     */
    private void copyBignat(byte[] src, byte[] dst) {
        Util.arrayCopy(src, (short)0, dst, (short)0, RSA_BLOCK_SIZE);
    }
    
    private void copyPoint(byte[] src, byte[] dst) {
        Util.arrayCopy(src, (short)0, dst, (short)0, BIGNAT_SIZE);
    }
    
    private boolean isZero(byte[] a) {
        for (short i = 0; i < RSA_BLOCK_SIZE; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }
    
    private boolean isPointZero(byte[] a) {
        for (short i = 0; i < BIGNAT_SIZE; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }
    
    private boolean isEqual(byte[] a, byte[] b) {
        return compare(a, b) == 0;
    }
    
    private void prependZeros(byte[] src, short srcOff, short srcLen,
                             byte[] dst, short dstOff, short dstLen) {
        // Safety check: source must not be larger than destination
        if (srcLen > dstLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short zeros = (short)(dstLen - srcLen);
        Util.arrayFillNonAtomic(dst, dstOff, zeros, (byte)0);
        Util.arrayCopy(src, srcOff, dst, (short)(dstOff + zeros), srcLen);
    }
    
    private byte[] copyToRSASize(byte[] small) {
        Util.arrayFillNonAtomic(tmp6, (short)0, RSA_BLOCK_SIZE, (byte)0);
        Util.arrayCopy(small, (short)0, tmp6, 
                      (short)(RSA_BLOCK_SIZE - small.length), (short)small.length);
        return tmp6;
    }
    
    /**
     * Verify if a point is on the P-256 curve
     * Checks: y^2 = x^3 + ax + b (mod p)
     */
    private boolean isPointOnCurve(byte[] x, byte[] y) {
        // Handle point at infinity
        if (isPointZero(x) && isPointZero(y)) {
            return true;
        }
        
        // Convert to full size for calculations
        // Use pre-allocated buffers instead of dynamic allocation
        prependZeros(x, (short)0, BIGNAT_SIZE, tempFull1, (short)0, RSA_BLOCK_SIZE);
        prependZeros(y, (short)0, BIGNAT_SIZE, tempFull2, (short)0, RSA_BLOCK_SIZE);
        
        // Calculate left side: y^2
        modSquare(tempFull2, tmp1);
        
        // Calculate right side: x^3 + ax + b
        // First: x^3
        modSquare(tempFull1, tmp2);
        modMul(tmp2, tempFull1, tmp3);
        
        // Then: ax (where a = P256_A)
        // Use tempFull3 for aValue instead of dynamic allocation
        prependZeros(P256_A, (short)0, COORD_SIZE, tempFull3, (short)0, RSA_BLOCK_SIZE);
        modMul(tempFull1, tempFull3, tmp2);
        
        // Add: x^3 + ax
        modAdd(tmp3, tmp2, tmp4);
        
        // Finally add b: x^3 + ax + b
        // Use tempFull4 for bValue instead of dynamic allocation
        prependZeros(P256_B, (short)0, COORD_SIZE, tempFull4, (short)0, RSA_BLOCK_SIZE);
        modAdd(tmp4, tempFull4, tmp2);
        
        // Compare y^2 with x^3 + ax + b
        return isEqual(tmp1, tmp2);
    }
    
    private boolean isPointEqual(byte[] x1, byte[] y1, byte[] x2, byte[] y2) {
        return Util.arrayCompare(x1, (short)0, x2, (short)0, BIGNAT_SIZE) == 0 &&
               Util.arrayCompare(y1, (short)0, y2, (short)0, BIGNAT_SIZE) == 0;
    }
    
    /**
     * Generate a cryptographically secure random scalar (private key)
     * @param buffer output buffer for the scalar
     * @param offset offset in the output buffer
     * @param length length of scalar (should be 32 for P-256)
     */
    public void generateRandomScalar(byte[] buffer, short offset, short length) {
        // Generate random bytes
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(buffer, offset, length);
        
        // Ensure the scalar is not zero (extremely rare but possible)
        // For simplicity, just set the LSB to 1 if all bytes are zero
        boolean allZero = true;
        for (short i = 0; i < length; i++) {
            if (buffer[(short)(offset + i)] != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            buffer[(short)(offset + length - 1)] = 1;
        }
    }
    
    /**
     * Perform scalar multiplication: scalar × point = resultPoint
     * @param scalar the scalar value (private key)
     * @param scalarOffset offset of scalar
     * @param point the input point (65 bytes, uncompressed format)
     * @param pointOffset offset of input point
     * @param resultPoint output buffer for result point (65 bytes)
     * @param resultOffset offset in output buffer
     * @return length of result point (always 65 for uncompressed P-256)
     */
    public short scalarMultiply(
        byte[] scalar, short scalarOffset,
        byte[] point, short pointOffset, 
        byte[] resultPoint, short resultOffset
    ) {
        // Validate point format
        if (point[pointOffset] != UNCOMPRESSED_POINT) {
            ISOException.throwIt(SW_INVALID_POINT_FORMAT);
        }
        
        // Extract X and Y coordinates from input point
        Util.arrayCopy(point, (short)(pointOffset + 1), pointX1, (short)1, COORD_SIZE);
        Util.arrayCopy(point, (short)(pointOffset + 1 + COORD_SIZE), pointY1, (short)1, COORD_SIZE);
        pointX1[0] = 0;  // Ensure MSB is 0 for Bignat operations
        pointY1[0] = 0;
        
        // Perform scalar multiplication using existing private method
        scalarMultiply(scalar, scalarOffset, pointX1, pointY1, pointX3, pointY3);
        
        // Format result as uncompressed point
        resultPoint[resultOffset] = UNCOMPRESSED_POINT;
        // Copy X coordinate (skip first byte which is 0)
        Util.arrayCopy(pointX3, (short)1, resultPoint, (short)(resultOffset + 1), COORD_SIZE);
        // Copy Y coordinate (skip first byte which is 0)
        Util.arrayCopy(pointY3, (short)1, resultPoint, (short)(resultOffset + 1 + COORD_SIZE), COORD_SIZE);
        
        return POINT_SIZE;
    }
    
    /**
     * Generate public key from private key (privateKey × G)
     * @param privateKey the private key
     * @param privateKeyOffset offset of private key
     * @param publicKey output buffer for public key (65 bytes)
     * @param publicKeyOffset offset in output buffer
     * @return length of public key (always 65 for uncompressed P-256)
     */
    public short generatePublicKey(
        byte[] privateKey, short privateKeyOffset,
        byte[] publicKey, short publicKeyOffset
    ) {
        return scalarMultiply(privateKey, privateKeyOffset, 
                            P256_G, (short)0, 
                            publicKey, publicKeyOffset);
    }
    
    /**
     * Clear all sensitive data
     */
    public void clear() {
        clearArray(tmp1);
        clearArray(tmp2);
        clearArray(tmp3);
        clearArray(tmp4);
        clearArray(tmp5);
        clearArray(tmp6);
        clearArray(pointX1);
        clearArray(pointY1);
        clearArray(pointX2);
        clearArray(pointY2);
        clearArray(pointX3);
        clearArray(pointY3);
        clearArray(rsaBuffer);
    }
    
    private void clearArray(byte[] array) {
        if (array != null) {
            Util.arrayFillNonAtomic(array, (short)0, (short)array.length, (byte)0);
        }
    }
}