//
//  AsymmetricKeys.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


public extension PublicKey {
  
	func encrypt(_ data: Data) throws -> Data {
    let dataPointer = (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count)
    var encryptedDataLength = SecKeyGetBlockSize(self.key)
    var encryptedData = [UInt8](repeating: 0, count: Int(encryptedDataLength))
    let result = SecKeyEncrypt(self.key, self.options.cryptoPadding, dataPointer, data.count, &encryptedData, &encryptedDataLength)
    if result != noErr { throw Exception.cannotEncryptData }
    return Data(bytes: UnsafePointer<UInt8>(encryptedData), count: encryptedDataLength)
  }
  
  
	func verify(_ data: Data, signature: Data) throws -> Bool {
    let hash = data.SHA1
    var result : OSStatus
    var pointer : UnsafePointer<UInt8>? = nil
    hash.withUnsafeBytes({ (ptr) in pointer = ptr})
    let signaturePointer = (signature as NSData).bytes.bindMemory(to: UInt8.self, capacity: signature.count)
    result = SecKeyRawVerify(self.key, self.options.signaturePadding, pointer!, hash.count, signaturePointer, signature.count)
    if result != 0 { return false } else { return true }
  }
}


public extension PrivateKey {
  
	func decrypt(_ data: Data) throws -> Data {
    let dataPointer = (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count)
    var decryptedDataLength = SecKeyGetBlockSize(self.key)
    var decryptedData = [UInt8](repeating: 0, count: Int(decryptedDataLength))
    let result = SecKeyDecrypt(self.key, self.options.cryptoPadding, dataPointer, data.count, &decryptedData, &decryptedDataLength)
    if result != noErr { throw Exception.cannotDecryptData }
    return Data(bytes: UnsafePointer<UInt8>(decryptedData), count: decryptedDataLength)
  }
  
  
	func signature(_ data: Data) throws -> Data {
    let hash = data.SHA1
    var signatureDataLength = SecKeyGetBlockSize(self.key)
    var signatureData = [UInt8](repeating: 0, count: Int(signatureDataLength))
    var pointer : UnsafePointer<UInt8>? = nil
    hash.withUnsafeBytes({ (ptr) in pointer = ptr})
    let status = SecKeyRawSign(self.key, self.options.signaturePadding, pointer!, hash.count, &signatureData, &signatureDataLength)
    if status != OSStatus(kCCSuccess) { throw Exception.cannotSignData }
    return Data(bytes: UnsafePointer<UInt8>(signatureData), count: signatureDataLength)
  }
}


public extension AsymmetricKeys {
  
  static func secKeyFromData(_ data:Data, publicKey:Bool) throws -> SecKey
  {
    func SecKeyBelowiOS9() throws -> SecKey
    {
      var query :[String:AnyObject] = [
        String(kSecClass): kSecClassKey,
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecAttrApplicationTag): TemporaryKeyTag as AnyObject ]
      SecItemDelete(query as CFDictionary)
      
      query[String(kSecValueData)] = data as AnyObject?
      if publicKey == true {
        query[String(kSecAttrKeyClass)] = kSecAttrKeyClassPublic
      } else {
        query[String(kSecAttrKeyClass)] = kSecAttrKeyClassPrivate
      }
      var persistentKey : CFTypeRef?
      var result : OSStatus = 0
      result = SecItemAdd(query as CFDictionary, &persistentKey)
      print(result)
      if result != noErr { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      
      query[String(kSecValueData)] = nil
      query[String(kSecReturnPersistentRef)] = nil
      query[String(kSecReturnRef)] = true as AnyObject?
      
      var keyPointer: AnyObject?
      result = SecItemCopyMatching(query as CFDictionary, &keyPointer)
      if result != noErr { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      return keyPointer as! SecKey
    }
    
    
    func SecKeyFromiOS10() throws -> SecKey
    {
      let error : UnsafeMutablePointer<Unmanaged<CFError>?>? = nil
      
      var query :[String:AnyObject] = [
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecAttrKeySizeInBits): 1024 as CFNumber ]
      if publicKey == true { query[String(kSecAttrKeyClass)] = kSecAttrKeyClassPublic }
      else { query[String(kSecAttrKeyClass)] = kSecAttrKeyClassPrivate }
      
      if #available(iOS 10.0, *)
      {
        let key = SecKeyCreateWithData(data as CFData, query as CFDictionary, error)
        if ((error) != nil || key == nil) { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
        return key!
      }
      else { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
    }
    
    if #available(iOS 10.0, *) { return try SecKeyFromiOS10() }
    else { return try SecKeyBelowiOS9() }
  }
}


public extension PublicKey {
  
	init(publicKey key: Data, options: AsymmetricKeys.Options = AsymmetricKeys.Options.Default) throws {
    
    func stripPublicKeyHeader(_ data:Data) throws -> Data {
      
      var buffer = [UInt8](repeating: 0, count: data.count)
      (data as NSData).getBytes(&buffer, length: data.count)
      var index = 0
      if buffer[index] != 0x30 { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      index += 1
      if buffer[index] > 0x80 { index += Int(buffer[index] - UInt8(0x80) + UInt8(1)) } else { index += 1 }
      let seqiod : [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
      if memcmp(&buffer, seqiod, 15) == 1 { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      
      index += 15
      
      if buffer[index] != 0x03 { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      index += 1
      if buffer[index] > 0x80 { index += Int(buffer[index] - UInt8(0x80) + UInt8(1)) } else { index += 1 }
      if buffer[index] != 0 { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      index += 1
      
      var noHeaderBuffer = [UInt8](repeating: 0, count: data.count - index)
      (data as NSData).getBytes(&noHeaderBuffer, range: NSRange(location: index, length: data.count - index))
      
      return Data(bytes: UnsafePointer<UInt8>(noHeaderBuffer), count: noHeaderBuffer.count)
    }
    
    
    func generatePublicKeyFromData() throws -> SecKey {
      
      guard var keyString = String(data: key, encoding: String.Encoding.utf8) else { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      
      if (keyString.hasPrefix("-----BEGIN PUBLIC KEY-----\n") && ( keyString.hasSuffix("-----END PUBLIC KEY-----\n") || keyString.hasSuffix("-----END PUBLIC KEY-----"))) {
        keyString = keyString.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        keyString = keyString.replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        keyString = keyString.replacingOccurrences(of: "\r", with: "")
        keyString = keyString.replacingOccurrences(of: "\n", with: "")
        keyString = keyString.replacingOccurrences(of: "\t", with: "")
        keyString = keyString.replacingOccurrences(of: " ", with: "")
        
        guard let data = Data(base64Encoded: keyString) else { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
        
        let noHeaderKey = try stripPublicKeyHeader(data)
        return try AsymmetricKeys.secKeyFromData(noHeaderKey, publicKey: true)
      }
      
      throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData
    }
    
    do { self.key = try generatePublicKeyFromData() }
    catch { throw error }
    self.options = options
    self.tag = nil
  }
}


public extension PrivateKey {
  
	init(privateKey key: Data, options: AsymmetricKeys.Options = AsymmetricKeys.Options.Default) throws {
    
    func stripPrivateKeyHeader(_ data: Data) throws -> Data {
      
      var buffer = [UInt8](repeating: 0, count: data.count)
      (data as NSData).getBytes(&buffer, length: data.count)
      
      var index = 22
      if buffer[index] != 0x04 { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      index += 1
      var length = buffer[index]
      index += 1
      let det = length & 0x80
      if det == 0 { length = length & 0x7f } else {
        var byteCount = length & 0x7f
        if Int(byteCount) + index > data.count { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
        var accum : UInt8 = 0
        var char = buffer[index]
        index += Int(byteCount)
        while byteCount != 0 {
          accum = (accum << 8) + char
          char += 1
          byteCount -= 1
        }
        length = accum
      }
      return data.subdata(in: Range<Data.Index>(uncheckedBounds: (index,index + Int(length))))
    }
    
    
    func generatePrivateKeyFromData() throws -> SecKey {
      
      guard var keyString = String(data: key, encoding: String.Encoding.utf8) else { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
      
      if (keyString.hasPrefix("-----BEGIN RSA PRIVATE KEY-----\n") && ( keyString.hasSuffix("-----END RSA PRIVATE KEY-----\n") || keyString.hasSuffix("-----END RSA PRIVATE KEY-----"))) {
        keyString = keyString.replacingOccurrences(of:"-----BEGIN RSA PRIVATE KEY-----", with: "")
        keyString = keyString.replacingOccurrences(of:"-----END RSA PRIVATE KEY-----", with: "")
        keyString = keyString.replacingOccurrences(of:"\r", with: "")
        keyString = keyString.replacingOccurrences(of:"\n", with: "")
        keyString = keyString.replacingOccurrences(of:"\t", with: "")
        keyString = keyString.replacingOccurrences(of:" ", with: "")
        
        guard let data = Data(base64Encoded: keyString) else { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
        return try AsymmetricKeys.secKeyFromData(data, publicKey: false)
        
      } else { throw AsymmetricKeys.Exception.cannotCreateSecKeyFromData }
    }
    
    
    self.key = try generatePrivateKeyFromData()
    self.options = options
    self.tag = nil
  }
}
