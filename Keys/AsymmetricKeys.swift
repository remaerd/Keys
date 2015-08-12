//
//  AsymmetricKeys.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import Foundation
import CommonCrypto


public struct AsymmetricKeys {
  
  typealias Keys = (publicKey:SecKey, privateKey:SecKey)
  
  
  public enum Error : ErrorType {
    case NotFound
    case DeleteError
  }
  
  
  var privateKey  : PrivateKey
  var publicKey   : PublicKey
  
  
  public struct Options {
    public let seperateValidationKey  : Bool
    public let keyType                : CFString
    public let keySize                : CFNumber
    public let padding                : SecPadding
  }
  
  
  public static var DefaultOptions : Options {
    return Options(seperateValidationKey: true, keyType: kSecAttrKeyTypeRSA, keySize: 2048 ,padding: SecPadding.PKCS1MD5)
  }
  
  
  public static func new(privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil, options:Options) -> AsymmetricKeys {
    let keys = AsymmetricKeys.newKey(privateTag, publicTag: publicTag, options: options)
    var validationKeys : Keys?
    if options.seperateValidationKey == true { validationKeys = AsymmetricKeys.newKey(privateTag, publicTag: publicTag, options: options) }
    return AsymmetricKeys(keys: keys, validationKeys: validationKeys, options: options)
  }
  
  
  private static func newKey(privateTag: String, publicTag: String, options: Options) -> Keys {
    let parameters = [String(kSecAttrKeyType):options.keyType, String(kSecAttrKeySizeInBits): options.keySize]
    let publicKeyPointer = UnsafeMutablePointer<SecKey?>()
    let privateKeyPointer = UnsafeMutablePointer<SecKey?>()
    SecKeyGeneratePair(parameters, publicKeyPointer, privateKeyPointer)
    return Keys(privateKeyPointer.memory!,publicKeyPointer.memory!)
  }
  
  
  private init(keys: Keys, validationKeys: Keys? = nil, options: Options = AsymmetricKeys.DefaultOptions) {
    self.privateKey = PrivateKey(key: keys.privateKey, options: options)
    self.publicKey = PublicKey(key: keys.publicKey, options: options)
  }
  
  
  public init(privateTag: String, publicTag: String, validationPrivateTag: String? = nil, validationPublicTag: String? = nil , options: Options = AsymmetricKeys.DefaultOptions) throws {
    do {
      let privateKey = try AsymmetricKeys.returnKeyWithTag(privateTag)
      let publicKey = try AsymmetricKeys.returnKeyWithTag(publicTag)
      self.privateKey = PrivateKey(key: privateKey, options: options)
      self.publicKey = PublicKey(key: publicKey, options: options)
    } catch {
      throw error
    }
  }
  
  
  private static func returnKeyWithTag(tag:String) throws -> SecKey {
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
  
  
  public static func removeKeyWithTag(tag:String) throws {
    let query = [
      String(kSecClassKey): kSecClass,
      String(kSecAttrApplicationTag): tag
    ]
    let result = SecItemDelete(query)
    if result != OSStatus(kCCSuccess) { throw Error.DeleteError }
  }
}


public struct PrivateKey : KeyType, Encryptable {
  
  public enum Error : ErrorType {
    case CannotEncryptData
    case CannotSignData
  }
  
  
  public let key      : SecKey
  public let options  : AsymmetricKeys.Options
  
  public var strength : Int {
    return 0
  }
  
  
  public init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}


public struct PublicKey : KeyType, Decryptable {
  
  public enum Error : ErrorType {
    case CannotDecryptData
    case CannotSignData
  }
  
  
  public var key      : SecKey
  public let options  : AsymmetricKeys.Options
  
  public var strength : Int {
    return 0
  }
  
  
  public init(key:SecKey, options: AsymmetricKeys.Options) {
    self.options = options
    self.key = key
  }
}