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
  
  public enum SymmetricKeyError : Error {
    case invalidKeySize
    case encryptError
    case decryptError
  }
  
  
  public let options    : Options
  public let cryptoKey  : Data
  public let IV         : Data
  public var hmacKey    : Data?
  
  
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
    self.cryptoKey = Data.randomData(options.keySize)
    self.IV = Data.randomData(kCCKeySizeAES128)
    if options.seperateKey == true { self.hmacKey = Data.randomData(options.keySize) }
    self.options = options
  }
  
  
  public init(key: Data, IV: Data = Data(), options: Options = SymmetricKey.DefaultOptions) throws {
    if options.seperateKey == true
    {
      if key.count / 2 != options.keySize { throw SymmetricKeyError.invalidKeySize }
      let keySize = key.count / 2
      let keyData = NSMutableData(length: keySize)!
      let hmacData = NSMutableData(length: keySize)!
      (key as NSData).getBytes(keyData.mutableBytes, length: keySize)
      (key as NSData).getBytes(hmacData.mutableBytes, range: NSRange(location: keySize,length: keySize))
      self.cryptoKey = keyData as Data
      self.hmacKey = hmacData as Data
    } else {
      if key.count != options.keySize { throw SymmetricKeyError.invalidKeySize }
      self.cryptoKey = key
    }
    self.IV = IV
    self.options = options
  }

  
  public func encrypt(_ data: Data) throws -> Data {
    let encryptedData = NSMutableData(length: data.count + self.options.algoritmBlockSize)!
    var encryptedMoved : Int = 0
    var keyPointer : UnsafePointer<UInt8>? = nil
    self.cryptoKey.withUnsafeBytes({ (ptr) in keyPointer = ptr})
    var ivPointer : UnsafePointer<UInt8>? = nil
    self.IV.withUnsafeBytes({ (ptr) in ivPointer = ptr})
    let result = CCCrypt(CCOperation(kCCEncrypt), self.options.algoritm, self.options.options, keyPointer, self.cryptoKey.count, ivPointer, (data as NSData).bytes, data.count, encryptedData.mutableBytes, encryptedData.length, &encryptedMoved)
    encryptedData.length = encryptedMoved
    if result != CCCryptorStatus(kCCSuccess) { throw SymmetricKeyError.encryptError }
    else { return encryptedData as Data }
  }
  
  
  public func decrypt(_ data: Data) throws -> Data {
    let decryptedData = NSMutableData(length: data.count + self.options.algoritmBlockSize)!
    var decryptedMoved = 0
    var keyPointer : UnsafePointer<UInt8>? = nil
    self.cryptoKey.withUnsafeBytes({ (ptr) in keyPointer = ptr})
    var ivPointer : UnsafePointer<UInt8>? = nil
    self.IV.withUnsafeBytes({ (ptr) in ivPointer = ptr})
    let result = CCCrypt(CCOperation(kCCDecrypt), self.options.algoritm, self.options.options, keyPointer, self.cryptoKey.count, ivPointer, (data as NSData).bytes, data.count, decryptedData.mutableBytes, decryptedData.length, &decryptedMoved)
    decryptedData.length = decryptedMoved
    if result != CCCryptorStatus(kCCSuccess) { throw SymmetricKeyError.decryptError }
    else { return decryptedData as Data }
  }
  
  
  public func signature(_ data: Data) throws -> Data {
    let hash = data.SHA256
    var key = self.hmacKey
    if key == nil { key = self.cryptoKey }
    let signature = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
    CCHmac(self.options.hmac, (key! as NSData).bytes, key!.count, (hash as NSData).bytes, hash.count, signature.mutableBytes)
    return signature as Data
  }
  
  
  public func verify(_ data: Data, signature: Data) throws -> Bool {
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

