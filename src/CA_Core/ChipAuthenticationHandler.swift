//
//  ChipAuthenticationHandler.swift
//  NFCPassportReader
//
//  CA认证核心实现 - 处理芯片认证的主要逻辑
//

import Foundation
import OSLog
import OpenSSL

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 15, *)
class ChipAuthenticationHandler {
    
    private static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00
    private static let ENC_MODE : UInt8 = 0x1
    private static let MAC_MODE : UInt8 = 0x2
    private static let PACE_MODE : UInt8 = 0x3

    private static let COMMAND_CHAINING_CHUNK_SIZE = 224

    var tagReader : TagReader?
    var gaSegments = [[UInt8]]()
    
    // 存储从DG14解析出的CA信息
    var chipAuthInfos = [Int:ChipAuthenticationInfo]()  // keyId -> ChipAuthenticationInfo映射
    var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()  // 公钥信息列表
    
    var isChipAuthenticationSupported : Bool = false
    
    // 初始化：从DG14中提取CA相关信息
    public init(dg14 : DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader
        
        // 遍历DG14中的安全信息
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                let keyId = cai.getKeyId()
                chipAuthInfos[keyId] = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append(capki)
            }
        }
        
        // 如果有公钥信息，则支持CA
        if chipAuthPublicKeyInfos.count > 0 {
            isChipAuthenticationSupported = true
        }
    }

    // 执行CA认证的主入口
    public func doChipAuthentication() async throws  {
                
        Logger.chipAuth.info( "Performing Chip Authentication - number of public keys found - \(self.chipAuthPublicKeyInfos.count)" )
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported( "ChipAuthentication not supported" )
        }
        
        var success = false
        // 尝试使用每个公钥进行认证
        for pubKey in chipAuthPublicKeyInfos {
            do {
                success = try await self.doChipAuthentication( with: pubKey)
                if success {
                    break
                }
            } catch {
                // 尝试下一个密钥
            }
        }
        
        if !success {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
    }
    
    // 使用特定公钥信息执行CA认证
    private func doChipAuthentication( with chipAuthPublicKeyInfo : ChipAuthenticationPublicKeyInfo ) async throws -> Bool {
        
        // 获取keyId和OID
        // 注意：有些护照可能没有ChipAuthInfo，需要从公钥OID推断
        let keyId = chipAuthPublicKeyInfo.keyId
        let chipAuthInfoOID : String
        if let chipAuthInfo = chipAuthInfos[keyId ?? 0] {
            chipAuthInfoOID = chipAuthInfo.oid
        } else {
            // 从公钥OID推断CA OID
            if let oid = inferOID( fromPublicKeyOID:chipAuthPublicKeyInfo.oid) {
                chipAuthInfoOID = oid
            } else {
                return false
            }
        }
        
        try await self.doCA( keyId: keyId, encryptionDetailsOID: chipAuthInfoOID, publicKey: chipAuthPublicKeyInfo.pubKey )
        return true
    }
    
    /// 从公钥类型推断OID - 用于处理缺少ChipAuthInfo的情况
    /// 法国护照等可能出现这种情况
    private func inferOID(fromPublicKeyOID: String ) -> String? {
        if fromPublicKeyOID == SecurityInfo.ID_PK_ECDH_OID {
            Logger.chipAuth.warning("No ChipAuthenticationInfo - guessing its id-CA-ECDH-3DES-CBC-CBC");
            return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID
        } else if fromPublicKeyOID == SecurityInfo.ID_PK_DH_OID {
            Logger.chipAuth.warning("No ChipAuthenticationInfo - guessing its id-CA-DH-3DES-CBC-CBC");
            return SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
        }
        
        Logger.chipAuth.warning("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID \(fromPublicKeyOID)")
        return nil;
    }
    
    // CA认证的核心实现
    private func doCA( keyId: Int?, encryptionDetailsOID oid: String, publicKey: OpaquePointer) async throws {
        
        // 1. 生成临时密钥对（基于DG14中的公钥参数）
        // 适用于EC和DH密钥
        var ephemeralKeyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(publicKey, nil)
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)
        EVP_PKEY_CTX_free(pctx)
        
        // 2. 发送公钥到护照
        try await sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: ephemeralKeyPair!)
            
        Logger.chipAuth.debug( "Public Key successfully sent to passport!" )
        
        // 3. 使用我们的私钥和护照的公钥计算共享密钥
        // （护照会使用它的私钥和我们的公钥做相同计算）
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair:ephemeralKeyPair!, publicKey:publicKey)
        
        // 4. 使用新的共享密钥重启安全消息
        try restartSecureMessaging( oid : oid, sharedSecret : sharedSecret, maxTranceiveLength : 1, shouldCheckMAC : true)
    }
    
    // 发送公钥到护照
    private func sendPublicKey(oid : String, keyId : Int?, pcdPublicKey : OpaquePointer) async throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        guard let keyData = OpenSSLUtils.getPublicKeyData(from: pcdPublicKey) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data from public key" )
        }
        
        if cipherAlg.hasPrefix("DESede") {
            // DESede情况：使用MSE Set KAT命令
            var idData : [UInt8] = []
            if let keyId = keyId {
                idData = intToBytes( val:keyId, removePadding:true)
                idData = wrapDO( b:0x84, arr:idData)  // 标签0x84表示Key ID
            }
            let wrappedKeyData = wrapDO( b:0x91, arr:keyData)  // 标签0x91表示密钥数据
            _ = try await self.tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData))
        } else if cipherAlg.hasPrefix("AES") {
            // AES情况：使用MSE Set AT + General Authenticate命令
            _ = try await self.tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)
            let data = wrapDO(b: 0x80, arr:keyData)  // 标签0x80表示动态认证数据
            gaSegments = self.chunk(data: data, segmentSize: ChipAuthenticationHandler.COMMAND_CHAINING_CHUNK_SIZE )
            try await self.handleGeneralAuthentication()
        } else {
            throw NFCPassportReaderError.InvalidDataPassed("Cipher Algorithm \(cipherAlg) not supported")
        }
    }
    
    // 处理General Authenticate命令（可能需要命令链）
    private func handleGeneralAuthentication() async throws {
        repeat {
            // 取出下一个数据段
            let segment = gaSegments.removeFirst()
            let isLast = gaSegments.isEmpty
        
            // 发送命令
            _ = try await self.tagReader?.sendGeneralAuthenticate(data: segment, isLast: isLast)
        } while ( !gaSegments.isEmpty )
    }
        
    // 使用新的共享密钥重启安全消息
    private func restartSecureMessaging( oid : String, sharedSecret : [UInt8], maxTranceiveLength : Int, shouldCheckMAC : Bool) throws  {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)
        
        // 派生会话密钥
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        
        // SSC (Send Sequence Counter) 初始化为0
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        
        // 根据加密算法创建相应的安全消息对象
        if (cipherAlg.hasPrefix("DESede")) {
            Logger.chipAuth.info( "Restarting secure messaging using DESede encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            Logger.chipAuth.info( "Restarting secure messaging using AES encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else {
            Logger.chipAuth.error( "Not restarting secure messaging as unsupported cipher algorithm requested - \(cipherAlg)")
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm \(cipherAlg)" )
        }
    }
    
    
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
    
    /// 将数据分块，用于命令链
    func chunk( data : [UInt8], segmentSize: Int ) -> [[UInt8]] {
        return stride(from: 0, to: data.count, by: segmentSize).map {
            Array(data[$0 ..< Swift.min($0 + segmentSize, data.count)])
        }
    }
}

#endif