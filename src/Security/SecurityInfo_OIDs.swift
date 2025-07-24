//
//  SecurityInfo_OIDs.swift
//
//  CA认证相关的OID（对象标识符）定义
//

import Foundation

// MARK: - 芯片认证公钥OID
public struct CA_PublicKey_OIDs {
    // DH公钥
    static let ID_PK_DH_OID = "0.4.0.127.0.7.2.2.1.1"
    // ECDH公钥
    static let ID_PK_ECDH_OID = "0.4.0.127.0.7.2.2.1.2"
}

// MARK: - 芯片认证算法OID
public struct CA_Algorithm_OIDs {
    // DH + 3DES-CBC-CBC
    static let ID_CA_DH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.1.1"
    
    // DH + AES-CBC-CMAC
    static let ID_CA_DH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.1.2"
    static let ID_CA_DH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.1.3"
    static let ID_CA_DH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.1.4"
    
    // ECDH + 3DES-CBC-CBC
    static let ID_CA_ECDH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.2.1"
    
    // ECDH + AES-CBC-CMAC
    static let ID_CA_ECDH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.2.2"
    static let ID_CA_ECDH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.2.3"
    static let ID_CA_ECDH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.2.4"
}

// MARK: - OID结构说明
/*
 OID结构：
 - 0.4.0.127.0.7 - BSI (德国联邦信息安全办公室)
 - 2.2 - 智能卡相关
 - 1.x - 公钥类型
 - 3.x.x - CA算法
   - 3.1.x - DH算法
   - 3.2.x - ECDH算法
   
 算法组合：
 - 3DES-CBC-CBC: 用于旧版护照
 - AES-CBC-CMAC-128/192/256: 用于新版护照，数字表示密钥长度
 */

// MARK: - 算法映射
public struct CA_Algorithm_Mapping {
    
    // 从OID获取密钥协商算法
    static func getKeyAgreementAlgorithm(oid: String) -> String? {
        if oid.contains(".3.1.") {
            return "DH"
        } else if oid.contains(".3.2.") {
            return "ECDH"
        }
        return nil
    }
    
    // 从OID获取加密算法
    static func getCipherAlgorithm(oid: String) -> String? {
        if oid.hasSuffix(".1") {
            return "DESede"  // 3DES
        } else if oid.hasSuffix(".2") || oid.hasSuffix(".3") || oid.hasSuffix(".4") {
            return "AES"
        }
        return nil
    }
    
    // 从OID获取密钥长度
    static func getKeyLength(oid: String) -> Int? {
        if oid.hasSuffix(".1") || oid.hasSuffix(".2") {
            return 128
        } else if oid.hasSuffix(".3") {
            return 192
        } else if oid.hasSuffix(".4") {
            return 256
        }
        return nil
    }
}