//
//  AsymmetricKeys-OSX.swift
//  Keys
//
//  Created by Sean Cheng on 8/10/15.
//
//


import Security


public extension PublicKey {
  
  public func encrypt(data: NSData) throws -> NSData {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?> = nil
    let transform = SecEncryptTransformCreate(self.key, error)
    if transform.bytes != nil { throw Error.CannotEncryptData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, dataRef, error)
    if error != nil { throw Error.CannotEncryptData }
    let encryptedData = SecTransformExecute(transform, error) as? NSData
    if encryptedData == nil { throw Error.CannotEncryptData }
    return encryptedData!
  }
  
  
  public func verify(data: NSData, signature: NSData) throws -> Bool {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?> = nil
    let transform = SecVerifyTransformCreate(self.key, signature, error)
    if error != nil || transform == nil { throw error.memory!.takeRetainedValue() as NSError }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
    SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, dataRef, error)
    SecTransformSetAttribute(transform!, kSecPaddingKey, kSecPaddingPKCS1Key, error)
    SecTransformSetAttribute(transform!, kSecDigestTypeAttribute, kSecDigestSHA1, error)
    SecTransformSetAttribute(transform!, kSecDigestLengthAttribute, 160, error)
    if error != nil { throw error.memory!.takeRetainedValue() as NSError }
    let result = SecTransformExecute(transform!, error) as? Bool
    if error != nil { throw error.memory!.takeRetainedValue() as NSError }
    if result == true { return true }
    else { return false }
  }
}


public extension PrivateKey {
  
  public func decrypt(data: NSData) throws -> NSData {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?> = nil
    let transform = SecDecryptTransformCreate(self.key, error)
    if error != nil { throw Error.CannotDecryptData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, dataRef, error)
    if error != nil { throw Error.CannotDecryptData }
    let decryptedData = SecTransformExecute(transform, error) as? NSData
    if decryptedData == nil { throw Error.CannotDecryptData }
    return decryptedData!
  }
  
  
  public func signature(data: NSData) throws -> NSData {
    let error : UnsafeMutablePointer<Unmanaged<CFError>?> = nil
    let transform = SecSignTransformCreate(self.key, error)
    if transform == nil { throw Error.CannotSignData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
    SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, dataRef, error)
    SecTransformSetAttribute(transform!, kSecPaddingKey, kSecPaddingPKCS1Key, error)
    SecTransformSetAttribute(transform!, kSecDigestTypeAttribute, kSecDigestSHA1, error)
    SecTransformSetAttribute(transform!, kSecDigestLengthAttribute, 160, error)
    if error != nil { throw Error.CannotSignData }
    let signature = SecTransformExecute(transform!, error) as? NSData
    if signature == nil { throw Error.CannotSignData }
    return signature!
  }
}


public extension AsymmetricKeys {
  
  static func secKeyFromData(data:NSData, publicKey: Bool) throws -> SecKey {
    
    let query :[String:AnyObject] = [
      String(kSecClass): kSecClassKey,
      String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
      String(kSecAttrApplicationTag): TemporaryKeyTag ]
    SecItemDelete(query)
    
    var result : OSStatus = 0
    var format : SecExternalFormat = SecExternalFormat.FormatOpenSSL
    var itemType : SecExternalItemType
    if publicKey == true { itemType = SecExternalItemType.ItemTypePublicKey }
    else { itemType = SecExternalItemType.ItemTypePrivateKey }
    var items : CFArray?
    result = SecItemImport(data, nil, &format, &itemType, SecItemImportExportFlags.PemArmour, nil, nil, &items)
    
    if result != noErr { throw Error.CannotCreateSecKeyFromData }
    return (items! as [AnyObject])[0] as! SecKey
  }
}


public extension PublicKey {
  
  public init(publicKey key: NSData) throws {
    self.key = try AsymmetricKeys.secKeyFromData(key, publicKey: true)
    self.options = AsymmetricKeys.Options.Default
    self.tag = nil
  }
}


public extension PrivateKey {
  
  public init(privateKey key: NSData) throws {
    self.key = try AsymmetricKeys.secKeyFromData(key, publicKey: false)
    self.options = AsymmetricKeys.Options.Default
    self.tag = nil
  }
}