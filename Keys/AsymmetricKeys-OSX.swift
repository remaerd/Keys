//
//  AsymmetricKeys-OSX.swift
//  Keys
//
//  Created by Sean Cheng on 8/10/15.
//
//


import Security


public extension PrivateKey {
  
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
    let hash = data.hash(HashType.SHA256)
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
  
  
//  public func encryptThenMac(data: NSData) throws -> NSData {
//    return NSData()
//  }
}


public extension PublicKey {
  
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
    let hash = data.hash(HashType.SHA256)
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
  
  
//  public func verifyThenDecrypt(data: NSData) throws -> NSData {
//    return NSData()
//  }
}

