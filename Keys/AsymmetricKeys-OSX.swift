//
//  AsymmetricKeys-OSX.swift
//  Keys
//
//  Created by Sean Cheng on 8/10/15.
//
//


import Security


public extension AsymmetricKey {
  
  public func encrypt(data: NSData) throws -> NSData {
    let error = UnsafeMutablePointer<Unmanaged<CFError>?>()
    let transform = SecEncryptTransformCreate(self.key, error)
    if transform.bytes != nil { throw Error.CannotEncryptData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, dataRef, error)
    if error != nil { throw Error.CannotEncryptData }
    let encryptedData = SecTransformExecute(transform, error) as? NSData
    if encryptedData == nil { throw Error.CannotEncryptData }
    return encryptedData!
  }
  
  
  public func signature(data: NSData) throws -> NSData {
    let hash = data.SHA256
    let error = UnsafeMutablePointer<Unmanaged<CFError>?>()
    let transform = SecSignTransformCreate(self.key, error)
    if transform == nil { throw Error.CannotSignData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(hash.bytes), hash.length)
    SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, dataRef, error)
    if error != nil { throw Error.CannotSignData }
    let signature = SecTransformExecute(transform!, error) as? NSData
    if signature == nil { throw Error.CannotSignData }
    return signature!
  }
  
  
  public func decrypt(data: NSData) throws -> NSData {
    let error = UnsafeMutablePointer<Unmanaged<CFError>?>()
    let transform = SecDecryptTransformCreate(self.key, error)
    if error != nil { throw Error.CannotDecryptData }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(data.bytes), data.length)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, dataRef, error)
    if error != nil { throw Error.CannotDecryptData }
    let decryptedData = SecTransformExecute(transform, error) as? NSData
    if decryptedData == nil { throw Error.CannotDecryptData }
    return decryptedData!
  }
  
  
  public func verify(data: NSData, signature: NSData) -> Bool {
    let hash = data.SHA256
    let error = UnsafeMutablePointer<Unmanaged<CFError>?>()
    let signatureRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(signature.bytes), signature.length)
    let transform = SecVerifyTransformCreate(self.key, signatureRef, error)
    if error != nil || transform == nil { return false }
    let dataRef = CFDataCreate(kCFAllocatorDefault, UnsafePointer<UInt8>(hash.bytes), hash.length)
    SecTransformSetAttribute(transform!, kSecTransformInputAttributeName, dataRef, error)
    if error != nil { return false }
    let result = SecTransformExecute(transform!, error) as? Bool
    if result == true { return true }
    else { return false }
  }
}


public extension AsymmetricKey {
  
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


public extension AsymmetricKey {
  
  public init(publicKey key: NSData) throws {

    self.key = try AsymmetricKey.secKeyFromData(key, publicKey: true)
    self.options = Options.Default
  }
  
  
  public init(privateKey key: NSData) throws {
    self.key = try AsymmetricKey.secKeyFromData(key, publicKey: false)
    self.options = Options.Default
  }
}