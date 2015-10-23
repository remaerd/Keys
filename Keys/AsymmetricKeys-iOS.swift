//
//  AsymmetricKeys.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


public extension AsymmetricKey {
  
  public func encrypt(data: NSData) throws -> NSData {
    let dataPointer = UnsafePointer<UInt8>(data.bytes)
    var encryptedDataLength = SecKeyGetBlockSize(self.key)
    var encryptedData = [UInt8](count: Int(encryptedDataLength), repeatedValue: 0)
    let result = SecKeyEncrypt(self.key, self.options.padding, dataPointer, data.length, &encryptedData, &encryptedDataLength)
    if result != noErr { throw Error.CannotEncryptData }
    return NSData(bytes: encryptedData, length: encryptedDataLength)
  }
  
  
  public func signature(data: NSData) throws -> NSData {
    let hash = data.SHA256
    let hashPointer = UnsafePointer<UInt8>(hash.bytes)
    let signaturePointer = UnsafeMutablePointer<UInt8>()
    let signatureLength = UnsafeMutablePointer<Int>()
    SecKeyRawSign(self.key, self.options.padding, hashPointer, hash.length, signaturePointer, signatureLength)
    let signature = NSData(bytesNoCopy: signaturePointer, length: signatureLength.memory)
    return signature
  }
  
  
  public func decrypt(data: NSData) throws -> NSData {
    let dataPointer = UnsafePointer<UInt8>(data.bytes)
    var decryptedDataLength = SecKeyGetBlockSize(self.key)
    var decryptedData = [UInt8](count: Int(decryptedDataLength), repeatedValue: 0)
    let result = SecKeyDecrypt(self.key, self.options.padding, dataPointer, data.length, &decryptedData, &decryptedDataLength)
    if result != noErr { throw Error.CannotDecryptData }
    return NSData(bytes: decryptedData, length: decryptedDataLength)
  }
  
  
  public func verify(data: NSData, signature: NSData) -> Bool {
    let hash = data.SHA256
    let hashPointer = UnsafePointer<UInt8>(hash.bytes)
    let signaturePointer = UnsafePointer<UInt8>(signature.bytes)
    let result = SecKeyRawVerify(self.key, self.options.padding, hashPointer, hash.length, signaturePointer, signature.length)
    if result != 0 { return false }
    else { return false }
  }
}


public extension AsymmetricKey {
  
  static func secKeyFromData(data:NSData, publicKey:Bool) throws -> SecKey {
    
    var query :[String:AnyObject] = [
      String(kSecClass): kSecClassKey,
      String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
      String(kSecAttrApplicationTag): TemporaryKeyTag ]
    SecItemDelete(query)
    
    query[String(kSecValueData)] = data
    if publicKey == true {
      query[String(kSecAttrKeyClass)] = kSecAttrKeyClassPublic
    } else {
      query[String(kSecAttrKeyClass)] = kSecAttrKeyClassPrivate
    }
    var persistentKey : CFTypeRef?
    var result : OSStatus = 0
    result = SecItemAdd(query, &persistentKey)
    if result != noErr { throw Error.CannotCreateSecKeyFromData }
    
    query[String(kSecValueData)] = nil
    query[String(kSecReturnPersistentRef)] = nil
    query[String(kSecReturnRef)] = true
    
    var keyPointer: AnyObject?
    result = SecItemCopyMatching(query, &keyPointer)
    if result != noErr { throw Error.CannotCreateSecKeyFromData }
    return keyPointer as! SecKey
  }
}


public extension AsymmetricKey {
  
  public init(publicKey key: NSData) throws  {
    
    func stripPublicKeyHeader(data:NSData) throws -> NSData {
      
      var buffer = [UInt8](count:data.length, repeatedValue:0)
      data.getBytes(&buffer, length: data.length)
      var index = 0
      if buffer[index++] != 0x30 { throw Error.CannotCreateSecKeyFromData }
      if buffer[index] > 0x80 { index += Int(buffer[index] - UInt8(0x80) + UInt8(1)) } else { index++ }
      
      let seqiod : [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
      if memcmp(&buffer, seqiod, 15) == 1 { throw Error.CannotCreateSecKeyFromData }
      
      index += 15
      
      if buffer[index++] != 0x03 { throw Error.CannotCreateSecKeyFromData }
      if buffer[index] > 0x80 { index += Int(buffer[index] - UInt8(0x80) + UInt8(1)) } else { index++ }
      if buffer[index++] != 0 { throw Error.CannotCreateSecKeyFromData }
      
      var noHeaderBuffer = [UInt8](count: data.length - index, repeatedValue: 0)
      data.getBytes(&noHeaderBuffer, range: NSRange(location: index, length: data.length - index))
      
      return NSData(bytes: noHeaderBuffer, length: noHeaderBuffer.count)
    }
    
    
    func generatePublicKeyFromData() throws -> SecKey {
      
      guard var keyString = String(data: key, encoding: NSUTF8StringEncoding) else { throw Error.CannotCreateSecKeyFromData }
      
      if (keyString.hasPrefix("-----BEGIN PUBLIC KEY-----\n") && ( keyString.hasSuffix("-----END PUBLIC KEY-----\n") || keyString.hasSuffix("-----END PUBLIC KEY-----"))) {
        keyString = keyString.stringByReplacingOccurrencesOfString("-----BEGIN PUBLIC KEY-----", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("-----END PUBLIC KEY-----", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("\r", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("\n", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("\t", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString(" ", withString: "")
        
        guard let data = NSData(base64EncodedString: keyString, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)
          else {  throw Error.CannotCreateSecKeyFromData }
        
        let noHeaderKey = try stripPublicKeyHeader(data)
        return try AsymmetricKey.secKeyFromData(noHeaderKey, publicKey: true)
      }
      
      throw Error.CannotCreateSecKeyFromData
    }
    
    self.options = Options.Default
    do { self.key = try generatePublicKeyFromData() }
    catch { throw error }
  }
}


public extension AsymmetricKey {
  
  public init(privateKey key: NSData) throws {
    
    func stripPrivateKeyHeader(data: NSData) throws -> NSData {
      
      var buffer = [UInt8](count:data.length, repeatedValue:0)
      data.getBytes(&buffer, length: data.length)
      
      var index = 22
      if buffer[index++] != 0x04 { throw Error.CannotCreateSecKeyFromData }
      var length = buffer[index++]
      let det = length & 0x80
      if det == 0 { length = length & 0x7f } else {
        var byteCount = length & 0x7f
        if Int(byteCount) + index > data.length { throw Error.CannotCreateSecKeyFromData }
        var accum : UInt8 = 0
        var char = buffer[index]
        index += Int(byteCount)
        while byteCount != 0 {
          accum = (accum << 8) + char
          char++
          byteCount--
        }
        length = accum
      }
      return data.subdataWithRange(NSRange(location: index, length: Int(length)))
    }
    
    
    func generatePrivateKeyFromData() throws -> SecKey {
      
      guard var keyString = String(data: key, encoding: NSUTF8StringEncoding) else { throw Error.CannotCreateSecKeyFromData }
      
      if (keyString.hasPrefix("-----BEGIN RSA PRIVATE KEY-----\n") && ( keyString.hasSuffix("-----END RSA PRIVATE KEY-----\n") || keyString.hasSuffix("-----END RSA PRIVATE KEY-----"))) {
        keyString = keyString.stringByReplacingOccurrencesOfString("-----BEGIN RSA PRIVATE KEY-----", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("-----END RSA PRIVATE KEY-----", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("\r", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("\n", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString("\t", withString: "")
        keyString = keyString.stringByReplacingOccurrencesOfString(" ", withString: "")
        
        guard let data = NSData(base64EncodedString: keyString, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)
          else {  throw Error.CannotCreateSecKeyFromData }
        
        return try AsymmetricKey.secKeyFromData(data, publicKey: false)
        
      } else { throw Error.CannotCreateSecKeyFromData }
    }
    
    
    self.key = try generatePrivateKeyFromData()
    self.options = Options.Default
  }
}
