    /// The  MSE Set AT for Chip Authentication.
    /// This command is the first command that is sent in the "AES" case.
    /// For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId.
    ///
    /// NOTE THIS IS CURRENTLY UNTESTED
    /// - Parameter oid the OID
    /// - Parameter keyId the keyId or {@code null}
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSESetATIntAuth( oid: String, keyId: Int? ) async throws -> ResponseAPDU {
        
        let cmd : NFCISO7816APDU
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        
        if let keyId = keyId, keyId != 0 {
            let keyIdBytes = wrapDO(b:0x84, arr:intToBytes(val:keyId, removePadding: true))
            let data = oidBytes + keyIdBytes
            
            cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: 256)
            
        } else {
            cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(oidBytes), expectedResponseLength: 256)
        }
        
        return try await send( cmd: cmd )
    }
    
    func sendMSESetATMutualAuth( oid: String, keyType: UInt8 ) async throws -> ResponseAPDU {
        
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        let keyTypeBytes = wrapDO( b: 0x83, arr:[keyType])
        
        let data = oidBytes + keyTypeBytes
            
        let cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0xC1, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: -1)
        
        return try await send( cmd: cmd )
    }
	
	
	
	    /// Sends a General Authenticate command.
    /// This command is the second command that is sent in the "AES" case.
    /// - Parameter data data to be sent, without the {@code 0x7C} prefix (this method will add it)
    /// - Parameter lengthExpected the expected length defaults to 256
    /// - Parameter isLast indicates whether this is the last command in the chain
    /// - Parameter completed the complete handler - returns the dynamic authentication data without the {@code 0x7C} prefix (this method will remove it) or an error
    func sendGeneralAuthenticate( data : [UInt8], lengthExpected : Int = 256, isLast: Bool) async throws -> ResponseAPDU {

        let wrappedData = wrapDO(b:0x7C, arr:data)
        let commandData = Data(wrappedData)
            
         // NOTE: Support of Protocol Response Data is CONDITIONAL:
         // It MUST be provided for version 2 but MUST NOT be provided for version 1.
         // So, we are expecting 0x7C (= tag), 0x00 (= length) here.
        
        // 0x10 is class command chaining
        let instructionClass : UInt8 = isLast ? 0x00 : 0x10
        let INS_BSI_GENERAL_AUTHENTICATE : UInt8 = 0x86
        
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: lengthExpected)
        var response : ResponseAPDU
        do {
            response = try await send( cmd: cmd )
            response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
        } catch {
            // If wrong length error
            if case NFCPassportReaderError.ResponseError(_, let sw1, let sw2) = error,
               sw1 == 0x67, sw2 == 0x00 {
                
                // Resend
                let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: 256)
                response = try await send( cmd: cmd )
                response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
            } else {
                throw error
            }
        }
        return response
    }