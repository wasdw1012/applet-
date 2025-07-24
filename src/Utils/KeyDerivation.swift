//
//  KeyDerivation.swift
//
//  CA认证中的密钥派生逻辑
//

import Foundation
import CryptoKit

@available(iOS 13, macOS 10.15, *)
class SecureMessagingSessionKeyGenerator {
    
    static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00
    
    enum SMSMode : UInt8 {
        case ENC_MODE = 0x1   // 加密密钥
        case MAC_MODE = 0x2   // MAC密钥
        case PACE_MODE = 0x3  // PACE模式
    }
    
    /// 从共享密钥派生会话密钥（加密或MAC密钥）
    /// - Parameters:
    ///   - keySeed: 共享密钥（通过DH/ECDH计算得到）
    ///   - cipherAlgName: 加密算法名称 ("DESede" 或 "AES")
    ///   - keyLength: 密钥长度（位）
    ///   - mode: 派生模式（ENC_MODE或MAC_MODE）
    /// - Returns: 派生的密钥
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, mode : SMSMode) throws  -> [UInt8] {
        return try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nil, mode: mode, paceKeyReference: SecureMessagingSessionKeyGenerator.NO_PACE_KEY_REFERENCE)
    }

    /// 密钥派生的核心实现
    /// 遵循ICAO 9303标准的密钥派生函数(KDF)
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, nonce : [UInt8]?, mode : SMSMode, paceKeyReference : UInt8) throws ->  [UInt8] {
        // 1. 根据加密算法和密钥长度确定哈希算法
        let digestAlgo = try inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg: cipherAlgName, keyLength: keyLength)
        
        // 2. 构建输入数据: keySeed || nonce(可选) || mode(4字节)
        let modeArr : [UInt8] = [0x00, 0x00, 0x00, mode.rawValue]
        var dataEls = [Data(keySeed)]
        if let nonce = nonce {
            dataEls.append( Data(nonce) )
        }
        dataEls.append( Data(modeArr) )
        
        // 3. 计算哈希
        let hashResult = try getHash(algo: digestAlgo, dataElements: dataEls)
        
        // 4. 根据算法和密钥长度截取相应的密钥字节
        var keyBytes : [UInt8]
        if cipherAlgName == "DESede" || cipherAlgName == "3DES" {
            // 3DES密钥派生 (遵循TR-SAC 1.01, 4.2.1)
            switch(keyLength) {
                case 112, 128:
                    // 3DES使用EDE模式：
                    // K1 = hashResult[0:8]  (E - 加密)
                    // K2 = hashResult[8:16] (D - 解密)
                    // K3 = hashResult[0:8]  (E - 加密，重复K1)
                    keyBytes = [UInt8](hashResult[0..<16] + hashResult[0..<8])
                    break;
                default:
                    throw NFCPassportReaderError.InvalidDataPassed("Can only use DESede with 128-bit key length")
            }
        } else if cipherAlgName.lowercased() == "aes" || cipherAlgName.lowercased().hasPrefix("aes") {
            // AES密钥派生 (遵循TR-SAC 1.01, 4.2.2)
            switch(keyLength) {
                case 128:
                    keyBytes = [UInt8](hashResult[0..<16]) // 16字节 = 128位
                case 192:
                    keyBytes = [UInt8](hashResult[0..<24]) // 24字节 = 192位
                case 256:
                    keyBytes = [UInt8](hashResult[0..<32]) // 32字节 = 256位
                default:
                    throw NFCPassportReaderError.InvalidDataPassed("Can only use AES with 128-bit, 192-bit key or 256-bit length")
            }
        } else {
            throw NFCPassportReaderError.InvalidDataPassed( "Unsupported cipher algorithm used" )
        }
        
        return keyBytes
    }
    
    /// 根据加密算法和密钥长度推断哈希算法
    /// - 3DES和AES-128使用SHA-1
    /// - AES-192和AES-256使用SHA-256
    func inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation( cipherAlg : String, keyLength : Int) throws -> String {
        if cipherAlg == "DESede" || cipherAlg == "AES-128" {
            return "SHA1"
        }
        if cipherAlg == "AES" && keyLength == 128 {
            return "SHA1"
        }
        if cipherAlg == "AES-256" || cipherAlg ==  "AES-192" {
            return "SHA256"
        }
        if cipherAlg == "AES" && (keyLength == 192 || keyLength == 256) {
            return "SHA256"
        }
        
        throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm or key length")
    }
    
    /// 计算哈希值
    func getHash(algo: String, dataElements:[Data] ) throws -> [UInt8] {
        var hash : [UInt8]
        
        let algo = algo.lowercased()
        if algo == "sha1" {
            var hasher = Insecure.SHA1()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha256" {
            var hasher = SHA256()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha384" {
            var hasher = SHA384()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha512" {
            var hasher = SHA512()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else {
            throw NFCPassportReaderError.InvalidHashAlgorithmSpecified
        }
        
        return hash
    }
}

// MARK: - 密钥派生示例

/*
 CA认证密钥派生流程：
 
 1. 通过DH/ECDH计算共享密钥(sharedSecret)
 2. 使用KDF派生加密密钥：
    ksEnc = KDF(sharedSecret, "1")  // mode = 0x01
 3. 使用KDF派生MAC密钥：
    ksMac = KDF(sharedSecret, "2")  // mode = 0x02
 4. 使用派生的密钥建立新的安全消息通道
 
 KDF函数：
 - 输入：K_seed || mode (4字节)
 - 输出：Hash(input)的前n个字节
 
 其中n取决于算法：
 - 3DES: 24字节（实际192位，但K3=K1）
 - AES-128: 16字节
 - AES-192: 24字节
 - AES-256: 32字节
 */