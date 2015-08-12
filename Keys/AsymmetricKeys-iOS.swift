//
//  AsymmetricKeys.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


public extension PrivateKey {
  
  public func encrypt(data: NSData) throws -> NSData {
    let dataPointer = UnsafePointer<UInt8>(data.bytes)
    let encryptedDataPointer = UnsafeMutablePointer<UInt8>()
    let encryptedDataLength = UnsafeMutablePointer<Int>()
    SecKeyEncrypt(self.key, self.options.padding, dataPointer, data.length, encryptedDataPointer, encryptedDataLength)
    let data = NSData(bytesNoCopy: encryptedDataPointer, length: encryptedDataLength.memory)
    return data
  }
  
  
  public func signature(data: NSData) throws -> NSData {
    let hash = data.hash(HashType.SHA256)
    let hashPointer = UnsafePointer<UInt8>(hash.bytes)
    let signaturePointer = UnsafeMutablePointer<UInt8>()
    let signatureLength = UnsafeMutablePointer<Int>()
    SecKeyRawSign(self.key, self.options.padding, hashPointer, hash.length, signaturePointer, signatureLength)
    let signature = NSData(bytesNoCopy: signaturePointer, length: signatureLength.memory)
    return signature
  }
}


public extension PublicKey {
  
  public func decrypt(data: NSData) throws -> NSData {
    let dataPointer = UnsafePointer<UInt8>(data.bytes)
    let decryptedDataPointer = UnsafeMutablePointer<UInt8>()
    let decryptedDataLength = UnsafeMutablePointer<Int>()
    SecKeyDecrypt(self.key, self.options.padding, dataPointer, data.length, decryptedDataPointer, decryptedDataLength)
    let decryptedData = NSData(bytesNoCopy: decryptedDataPointer, length: decryptedDataLength.memory)
    return decryptedData
  }
  
  
  public func verify(data: NSData, signature: NSData) -> Bool {
    let hash = data.hash(HashType.SHA256)
    let hashPointer = UnsafePointer<UInt8>(hash.bytes)
    let signaturePointer = UnsafePointer<UInt8>(signature.bytes)
    let result = SecKeyRawVerify(self.key, self.options.padding, hashPointer, hash.length, signaturePointer, signature.length)
    if result != 0 { return false }
    else { return false }
  }
}

