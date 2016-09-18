//
//  AsymmetricKeys-OSX.swift
//  Keys
//
//  Created by Sean Cheng on 8/10/15.
//
//


import Security


public extension PublicKey {
  
  public func encrypt(_ data: Data) throws -> Data {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?>? = nil
    let transform = SecEncryptTransformCreate(self.key, error)
    if transform.bytes != nil { throw Exception.cannotEncryptData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count), data.count)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, dataRef!, error)
    if error != nil { throw Exception.cannotEncryptData }
    let encryptedData = SecTransformExecute(transform, error) as? Data
    if encryptedData == nil { throw Exception.cannotEncryptData }
    return encryptedData!
  }
  
  
  public func verify(_ data: Data, signature: Data) throws -> Bool {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?>? = nil
    let transform = SecVerifyTransformCreate(self.key, signature as CFData?, error)
    if error != nil || transform == nil { throw Exception.cannotVerifyData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count), data.count)
    SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, dataRef!, error)
    SecTransformSetAttribute(transform!, kSecPaddingKey, kSecPaddingPKCS1Key, error)
    SecTransformSetAttribute(transform!, kSecDigestTypeAttribute, kSecDigestSHA1, error)
    SecTransformSetAttribute(transform!, kSecDigestLengthAttribute, 160 as CFTypeRef, error)
    if error != nil { throw Exception.cannotVerifyData }
    let result = SecTransformExecute(transform!, error) as? Bool
    if error != nil { throw Exception.cannotVerifyData }
    if result == true { return true }
    else { return false }
  }
}


public extension PrivateKey {
  
  public func decrypt(_ data: Data) throws -> Data {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?>? = nil
    let transform = SecDecryptTransformCreate(self.key, error)
    if error != nil { throw Exception.cannotDecryptData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count), data.count)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, dataRef!, error)
    if error != nil { throw Exception.cannotDecryptData }
    let decryptedData = SecTransformExecute(transform, error) as? Data
    if decryptedData == nil { throw Exception.cannotDecryptData }
    return decryptedData!
  }
  
  
  public func signature(_ data: Data) throws -> Data {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?>? = nil
    let transform = SecSignTransformCreate(self.key, error)
    if transform == nil { throw Exception.cannotSignData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count), data.count)
    SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, dataRef!, error)
    SecTransformSetAttribute(transform!, kSecPaddingKey, kSecPaddingPKCS1Key, error)
    SecTransformSetAttribute(transform!, kSecDigestTypeAttribute, kSecDigestSHA1, error)
    SecTransformSetAttribute(transform!, kSecDigestLengthAttribute, 160 as CFTypeRef, error)
    if error != nil { throw Exception.cannotSignData }
    let signature = SecTransformExecute(transform!, error) as? Data
    if signature == nil { throw Exception.cannotSignData }
    return signature!
  }
}


public extension AsymmetricKeys {
  
  static func secKeyFromData(_ data:Data, publicKey: Bool) throws -> SecKey {
    
    let query :[String:AnyObject] = [
      String(kSecClass): kSecClassKey,
      String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
      String(kSecAttrApplicationTag): TemporaryKeyTag as AnyObject ]
    SecItemDelete(query as CFDictionary)
    
    var result : OSStatus = 0
    var format : SecExternalFormat = SecExternalFormat.formatOpenSSL
    var itemType : SecExternalItemType
    if publicKey == true { itemType = SecExternalItemType.itemTypePublicKey }
    else { itemType = SecExternalItemType.itemTypePrivateKey }
    var items : CFArray?
    result = SecItemImport(data as CFData, nil, &format, &itemType, SecItemImportExportFlags.pemArmour, nil, nil, &items)
    
    if result != noErr { throw Exception.cannotCreateSecKeyFromData }
    return (items! as [AnyObject])[0] as! SecKey
  }
}


public extension PublicKey {
  
  public init(publicKey key: Data) throws {
    self.key = try AsymmetricKeys.secKeyFromData(key, publicKey: true)
    self.options = AsymmetricKeys.Options.Default
    self.tag = nil
  }
}


public extension PrivateKey {
  
  public init(privateKey key: Data) throws {
    self.key = try AsymmetricKeys.secKeyFromData(key, publicKey: false)
    self.options = AsymmetricKeys.Options.Default
    self.tag = nil
  }
}
