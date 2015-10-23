//
//  AsymmetricKeys.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import Foundation
import CommonCrypto


// 非对称密钥组。 用于加密需要传输到其他设备时用到的数据。
public struct AsymmetricKeys {
  
  public enum Error : ErrorType {
    case CannotCreateSecKeyFromData
    case NotFound
    case DeleteError
  }
  
  
  public typealias Keys = (publicKey:PublicKey, privateKey:PrivateKey)
  
  
  public var keys           : Keys
  public var validationKeys : Keys?
  var options               : Options
  
  
  public struct Options {
    public let seperateValidationKey  : Bool
    public let keyType                : CFString
    public let keySize                : CFNumber
    public let padding                : SecPadding
    public let tag                    : String
    
    
    public init(tag:String = TemporaryKeyTag, seperateKey:Bool,type:CFString,size:CFNumber, padding: SecPadding) {
      self.seperateValidationKey = seperateKey
      self.tag = tag
      self.keyType = type
      self.keySize = size
      self.padding = padding
    }
  }
  
  
  public static var DefaultOptions : Options {
    return Options(seperateKey: true, type: kSecAttrKeyTypeRSA, size: 2048 ,padding: SecPadding.PKCS1)
  }
  
  
  private static func generateSecKeys(options: Options) -> Keys {
    let parameters = [String(kSecAttrKeyType):options.keyType,
                      String(kSecAttrKeySizeInBits): options.keySize,
                      String(kSecAttrLabel): options.tag]
    var publicKeyPointer : SecKey?
    var privateKeyPointer : SecKey?
    SecKeyGeneratePair(parameters, &publicKeyPointer, &privateKeyPointer)
    let publicKey = PublicKey(key: publicKeyPointer!, options: options)
    let privateKey = PrivateKey(key: privateKeyPointer!, options: options)
    return Keys(publicKey,privateKey)
  }
  
  
  public init(options:Options = AsymmetricKeys.DefaultOptions) {
    self.options = options
    self.keys = AsymmetricKeys.generateSecKeys(options)
    if options.seperateValidationKey == true { self.validationKeys = AsymmetricKeys.generateSecKeys(options) }
  }
  
  
  private init(keys: Keys, validationKeys: Keys? = nil, options: Options = AsymmetricKeys.DefaultOptions) {
    self.keys = keys
    self.validationKeys = validationKeys
    self.options = options
  }
  
  
  public static func get(privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil , options: Options = AsymmetricKeys.DefaultOptions) throws -> AsymmetricKeys {
    
    
    func secKeyWithTag(tag:String) throws -> SecKey {
      let query = [
        String(kSecClassKey): kSecClass,
        String(kSecAttrApplicationTag): tag,
        String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
        String(kSecReturnRef): true
      ]
      let keyPointer = UnsafeMutablePointer<AnyObject?>()
      let result = SecItemCopyMatching(query, keyPointer)
      if result != OSStatus(kCCSuccess) { throw Error.NotFound }
      else { return keyPointer.memory as! SecKey }
    }
    
    
    func keysWithTags(privateTag:String, publicTag:String) throws -> Keys {
      let privateKeyRef = try secKeyWithTag(privateTag)
      let publicKeyRef = try secKeyWithTag(publicTag)
      let privateKey = PrivateKey(key: privateKeyRef, options: options)
      let publicKey = PublicKey(key: publicKeyRef, options: options)
      return Keys(publicKey,privateKey)
    }
    
    
    do {
      let keys = try keysWithTags(privateTag, publicTag: publicTag)
      var validationKeys : Keys?
      if let publicT = validationPublicTag, privateT = validationPrivateTag {
        validationKeys = try keysWithTags(privateT, publicTag: publicT)
      }
      return AsymmetricKeys(keys: keys, validationKeys: validationKeys, options: options)
    } catch {
      throw error
    }
  }
  
  
  public func save(privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil) throws {
    
  }
  
  
  public func remove() throws {
    
  }
  
  
  public static func removeKeyWithTag(tag:String) throws {
    let query = [
      String(kSecClassKey): kSecClass,
      String(kSecAttrApplicationTag): tag
    ]
    let result = SecItemDelete(query)
    if result != OSStatus(kCCSuccess) { throw Error.DeleteError }
  }
}


// 私钥。 用于加密与获得数据验证码
public struct PrivateKey : Decryptable {
  
  public enum Error : ErrorType {
    case CannotDecryptData
    case CannotSignData
  }
  
  
  public var tag      : String?
  public var key      : SecKey
  public var options  : AsymmetricKeys.Options
  
  
  private init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}


// 公钥。 用于解密与验证数据
public struct PublicKey : Encryptable {
  
  public enum Error : ErrorType {
    case CannotEncryptData
    case CannotSignData
  }
  
  
  public var tag      : String?
  public var key      : SecKey!
  public var options  : AsymmetricKeys.Options
  
  
  init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}