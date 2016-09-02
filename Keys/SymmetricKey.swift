//
//  SymmetricKey.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


// 对称密钥。 用于加密本地存储的数据。
public struct SymmetricKey : Encryptable, Decryptable {
  
  public enum Error : ErrorType {
    case InvalidKeySize
    case EncryptError
    case DecryptError
  }
  
  
  public let options    : Options
  public let cryptoKey  : NSData
  public let IV         : NSData
  public var hmacKey    : NSData?
  
  
  public struct Options {
    
    public let keySize     : Int
    public let seperateKey : Bool
    public let algoritm    : CCAlgorithm
    public let options     : CCOptions
    public let hmac        : CCHmacAlgorithm
    
    
    public var algoritmBlockSize : Int {
      switch self.algoritm {
      case CCAlgorithm(kCCAlgorithmAES): return kCCBlockSizeAES128
      case CCAlgorithm(kCCAlgorithmAES128): return kCCBlockSizeAES128
      default : return 0
      }
    }
  }
  
  
  public static var DefaultOptions : Options {
    return Options(keySize: kCCKeySizeAES256, seperateKey: true, algoritm: CCAlgorithm(kCCAlgorithmAES), options: CCOptions(kCCOptionPKCS7Padding), hmac: CCHmacAlgorithm(kCCHmacAlgSHA256))
  }
  
  
  public init(options:Options = DefaultOptions) {
    self.cryptoKey = NSData.randomData(options.keySize)
    self.IV = NSData.randomIV(kCCBlockSizeAES128)
    if options.seperateKey == true { self.hmacKey = NSData.randomData(options.keySize) }
    self.options = options
  }
  
  
  public init(key: NSData, IV: NSData = NSData(), options: Options = SymmetricKey.DefaultOptions) throws {
    if options.seperateKey == true {
      if key.length / 2 != options.keySize { throw Error.InvalidKeySize }
      let keySize = key.length / 2
      let keyData = NSMutableData(length: keySize)!
      let hmacData = NSMutableData(length: keySize)!
      key.getBytes(keyData.mutableBytes, length: keySize)
      key.getBytes(hmacData.mutableBytes, range: NSRange(location: keySize,length: keySize))
      self.cryptoKey = keyData
      self.hmacKey = hmacData
    } else {
      if key.length != options.keySize { throw Error.InvalidKeySize }
      self.cryptoKey = key
    }
    self.IV = IV
    self.options = options
  }

  
  public func encrypt(data: NSData) throws -> NSData {
    let encryptedData = NSMutableData(length: data.length + self.options.algoritmBlockSize)!
    var encryptedMoved : Int = 0
    let result = CCCrypt(CCOperation(kCCEncrypt), self.options.algoritm, self.options.options, self.cryptoKey.bytes, self.cryptoKey.length, self.IV.bytes, data.bytes, data.length, encryptedData.mutableBytes, encryptedData.length, &encryptedMoved)
    encryptedData.length = encryptedMoved
    if result != CCCryptorStatus(kCCSuccess) { throw Error.EncryptError }
    else { return encryptedData }
  }
  
  
  public func decrypt(data: NSData) throws -> NSData {
    let decryptedData = NSMutableData(length: data.length + self.options.algoritmBlockSize)!
    var decryptedMoved = 0
    let result = CCCrypt(CCOperation(kCCDecrypt), self.options.algoritm, self.options.options, self.cryptoKey.bytes, self.cryptoKey.length, self.IV.bytes, data.bytes, data.length, decryptedData.mutableBytes, decryptedData.length, &decryptedMoved)
    decryptedData.length = decryptedMoved
    if result != CCCryptorStatus(kCCSuccess) { throw Error.DecryptError }
    else { return decryptedData }
  }
  
  
  public func signature(data: NSData) throws -> NSData {
    let hash = data.SHA256
    var key = self.hmacKey
    if key == nil { key = self.cryptoKey }
    let signature = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
    CCHmac(self.options.hmac, key!.bytes, key!.length, hash.bytes, hash.length, signature.mutableBytes)
    return signature
  }
  
  
  public func verify(data: NSData, signature: NSData) throws -> Bool {
    do {
      let signatureData = try self.signature(data)
      if signatureData == signature { return true }
      else { return false }
    } catch {
      throw error
    }
  }
  
  
//  public func encryptThenMac(data: NSData) throws -> NSData {
//    return NSData()
//  }
//  
//  
//  public func verifyThenDecrypt(data: NSData) throws -> NSData {
//    return NSData()
//  }
}

