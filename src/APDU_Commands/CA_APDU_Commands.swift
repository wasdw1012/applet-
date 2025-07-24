//
//  CA_APDU_Commands.swift
//
//  CA认证相关的APDU命令
//

import Foundation

// MARK: - MSE (Manage Security Environment) 命令

/// MSE Set KAT (Key Agreement Template) - 用于DESede情况
/// CLA: 0x00
/// INS: 0x22 (MSE)
/// P1: 0x41 (Computation, Decipherment, Internal Auth, Key Agreement)
/// P2: 0xA6 (SET for Key Agreement)
func buildMSESetKAT(keyData: [UInt8], keyId: [UInt8]?) -> [UInt8] {
    var data = keyData
    if let keyId = keyId {
        data += keyId
    }
    
    // APDU: CLA INS P1 P2 Lc Data
    var apdu = [UInt8]()
    apdu.append(0x00)  // CLA
    apdu.append(0x22)  // INS - MSE
    apdu.append(0x41)  // P1
    apdu.append(0xA6)  // P2 - SET for Key Agreement
    apdu.append(UInt8(data.count))  // Lc
    apdu += data
    
    return apdu
}

/// MSE Set AT for Internal Authentication - 用于AES情况
/// CLA: 0x00
/// INS: 0x22 (MSE)
/// P1: 0x41 (Computation, Decipherment, Internal Auth, Key Agreement)
/// P2: 0xA4 (SET for Authentication)
func buildMSESetATIntAuth(oid: [UInt8], keyId: [UInt8]?) -> [UInt8] {
    var data = oid
    if let keyId = keyId {
        data += keyId
    }
    
    var apdu = [UInt8]()
    apdu.append(0x00)  // CLA
    apdu.append(0x22)  // INS - MSE
    apdu.append(0x41)  // P1
    apdu.append(0xA4)  // P2 - SET for Authentication
    apdu.append(UInt8(data.count))  // Lc
    apdu += data
    
    return apdu
}

// MARK: - General Authenticate 命令

/// General Authenticate - 用于密钥交换
/// CLA: 0x00 或 0x10 (命令链)
/// INS: 0x86
/// P1: 0x00
/// P2: 0x00
func buildGeneralAuthenticate(data: [UInt8], isCommandChaining: Bool) -> [UInt8] {
    var apdu = [UInt8]()
    apdu.append(isCommandChaining ? 0x10 : 0x00)  // CLA
    apdu.append(0x86)  // INS - General Authenticate
    apdu.append(0x00)  // P1
    apdu.append(0x00)  // P2
    
    // 添加长度和数据
    if data.count <= 255 {
        apdu.append(UInt8(data.count))  // Lc
    } else {
        // 扩展长度
        apdu.append(0x00)
        apdu.append(UInt8((data.count >> 8) & 0xFF))
        apdu.append(UInt8(data.count & 0xFF))
    }
    apdu += data
    
    // Le - 期望响应长度
    apdu.append(0x00)
    
    return apdu
}

// MARK: - 数据对象(DO)包装

/// 包装数据对象(DO) - Tag-Length-Value格式
func wrapDO(tag: UInt8, data: [UInt8]) -> [UInt8] {
    var result = [UInt8]()
    result.append(tag)
    
    // 编码长度
    if data.count <= 127 {
        result.append(UInt8(data.count))
    } else if data.count <= 255 {
        result.append(0x81)
        result.append(UInt8(data.count))
    } else {
        result.append(0x82)
        result.append(UInt8((data.count >> 8) & 0xFF))
        result.append(UInt8(data.count & 0xFF))
    }
    
    result += data
    return result
}

// MARK: - CA认证中使用的标签定义

public struct CA_Tags {
    static let DYNAMIC_AUTH_DATA: UInt8 = 0x7C  // 动态认证数据容器
    static let OID: UInt8 = 0x80               // OID (替换0x06)
    static let KEY_REFERENCE: UInt8 = 0x84     // 密钥引用/ID
    static let EPHEMERAL_PUBLIC_KEY: UInt8 = 0x91  // 临时公钥
    static let KEY_AGREEMENT_DATA: UInt8 = 0x80    // 密钥协商数据(AES情况)
    static let AUTHENTICATION_TOKEN: UInt8 = 0x85   // 认证令牌
    static let CA_PUBLIC_KEY: UInt8 = 0x86         // CA公钥
}

// MARK: - APDU响应处理

/// 解析General Authenticate响应
func parseGeneralAuthenticateResponse(response: [UInt8]) throws -> [UInt8] {
    // 响应格式: 7C Len Data
    guard response.count >= 4,
          response[0] == CA_Tags.DYNAMIC_AUTH_DATA else {
        throw CAError.invalidResponse
    }
    
    let (dataLength, lengthSize) = decodeLength(Array(response[1...]))
    let dataStart = 1 + lengthSize
    let dataEnd = dataStart + dataLength
    
    guard response.count >= dataEnd else {
        throw CAError.invalidResponseLength
    }
    
    return Array(response[dataStart..<dataEnd])
}

/// 解码ASN.1长度
func decodeLength(_ data: [UInt8]) -> (length: Int, size: Int) {
    if data[0] <= 0x7F {
        return (Int(data[0]), 1)
    } else if data[0] == 0x81 {
        return (Int(data[1]), 2)
    } else if data[0] == 0x82 {
        return (Int(data[1]) << 8 | Int(data[2]), 3)
    }
    return (0, 0)
}

enum CAError: Error {
    case invalidResponse
    case invalidResponseLength
}