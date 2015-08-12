//
//  Password.swift
//  Keys
//
//  Created by Sean Cheng on 8/8/15.
//
//

import Foundation
import CommonCrypto


public struct Password : KeyType {
  
  public enum Error : ErrorType {
    case CannotCreatePassword
  }
  
  
  public let salt     : NSData
  public let options  : Options
  public let rounds   : UInt32
  public let data     : NSData
  
  
  public struct Options {
    let keySize   : Int
    let saltSize  : Int
    let PBKDF     : CCPBKDFAlgorithm
    let PRF       : CCPseudoRandomAlgorithm
  }
  
  
  public static var DefaultOptions : Options {
    return Options(keySize: Int(CC_SHA512_DIGEST_LENGTH),
      saltSize: 8,
      PBKDF: CCPBKDFAlgorithm(kCCPBKDF2),
      PRF: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512))
  }
  
  
  public var strength : Int {
    return 0
  }
  
  
  public lazy var key : SymmetricKey = {
    let keySize = self.options.keySize / 2
    let keyBytes = UnsafeMutablePointer<Void>()
    let hmacBytes = UnsafeMutablePointer<Void>()
    self.data.getBytes(keyBytes)
    self.data.getBytes(hmacBytes, range: NSRange(location: keySize,length: keySize))
    let keyData = NSData(bytes: keyBytes, length: keySize)
    let hmacData = NSData(bytes: hmacBytes, length: keySize)
    return try! SymmetricKey(key: keyData, hmacKey: hmacData, IV: NSData())
  }()
  
  
  public static func new(strength: KeyStrength = KeyStrength.Regular) -> Password {
    let randomString = String.randomString(32)
    let key = try! Password(password: randomString)
    return key
  }
  
  
  public init(password:String, salt:NSData = NSData.randomData(Password.DefaultOptions.saltSize), roundCount: Int? = nil, options: Options = Password.DefaultOptions) throws {
    
    let derivedData = NSMutableData(length: options.keySize)!
    let saltBytes = UnsafePointer<UInt8>(salt.bytes)
    let saltLength = salt.length
    let password = password.dataUsingEncoding(NSUTF8StringEncoding)!
    let passwordPointer = UnsafePointer<Int8>(password.bytes)
    let passwordLength = password.length
    let derivedDataPointer = UnsafeMutablePointer<UInt8>(derivedData.mutableBytes)
    let derivedDataLength = derivedData.length
    let count: UInt32
    if roundCount != nil { count = UInt32(roundCount!) }
    else { count = CCCalibratePBKDF( options.PBKDF, passwordLength, saltLength, options.PRF, derivedDataLength, 1000 ) }
    
    let result = CCKeyDerivationPBKDF(options.PBKDF, passwordPointer, passwordLength, saltBytes, saltLength, options.PRF, count, derivedDataPointer, derivedDataLength)
    if Int(result) != kCCSuccess { throw Error.CannotCreatePassword }
    
    self.data = derivedData
    self.rounds = count
    self.salt = salt
    self.options = options
  }
  
  
  public mutating func encrypt(key:SymmetricKey) throws -> (key: NSData, hmac: NSData?, IV: NSData) {
    do {
      let encryptKey = try self.key.encrypt(key.cryptoKey)
      let IV = try self.key.encrypt(key.IV)
      var hmacKey : NSData?
      if key.hmacKey != nil { hmacKey = try self.key.encrypt(key.hmacKey!) }
      return (encryptKey, hmacKey, IV)
    } catch {
      throw error
    }
  }
  
  
  public mutating func decrypt(key:NSData, hmacKey: NSData?, IV: NSData, options: SymmetricKey.Options = SymmetricKey.DefaultOptions) throws -> SymmetricKey {
    do {
      let keyData = try self.key.decrypt(key)
      let IVData = try self.key.decrypt(IV)
      var hmacData : NSData?
      if hmacKey != nil { hmacData = try self.key.decrypt(hmacKey!) }
      let symmetricKey = try SymmetricKey(key: keyData, hmacKey: hmacData, IV: IVData, options: options)
      return symmetricKey
    } catch {
      throw error
    }
  }
}