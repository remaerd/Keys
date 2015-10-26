//
//  AsymmetricKeysTests.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import XCTest
@testable import Keys


class AsymmetricKeyTests: XCTestCase {
  
  func testOpenSSLKey() {
    let publicKeyData = NSData(contentsOfURL: NSBundle(forClass: self.classForCoder).URLForResource("keys-public", withExtension: "pem")!)!
    let privateKeyData = NSData(contentsOfURL: NSBundle(forClass: self.classForCoder).URLForResource("keys-private", withExtension: "pem")!)!
    let secretData = "Hello Me".dataUsingEncoding(NSUTF8StringEncoding)!
    do {
      let publicKey = try PublicKey(publicKey: publicKeyData)
      print(publicKey)
      let privateKey = try PrivateKey(privateKey: privateKeyData)
      print(privateKey)
      let secret = try publicKey.encrypt(secretData)
      let decryptedSecret = try privateKey.decrypt(secret)
      XCTAssertEqual(secretData, decryptedSecret)
      print(NSString(data: decryptedSecret, encoding: NSUTF8StringEncoding))
    } catch {
      XCTFail()
    }
  }
  
  
  func testAsymmetricKey() {
    let keys = AsymmetricKeys.generateKeyPair()
    let secretData = "Hello World".dataUsingEncoding(NSUTF8StringEncoding)!
    do {
      let secret = try keys.publicKey.encrypt(secretData)
      let decryptedSecret = try keys.privateKey.decrypt(secret)
      XCTAssertEqual(secretData, decryptedSecret)
    } catch {
      XCTFail()
    }
  }
  
  
  func testDecryptNodeJSEncryptedData() {
    let encryptedString = "POeVBWNhsXOcZAw8R/pv6edPIdVM9p1Ux47BMKuWHggLfkUpT3LaGKzwcYA2zInpBnf4GEZzq7wR5/LO14QvCMLWPwgQ/SYlgFkaPA4+lIsUIGEMRGD76YPwmiulgctHiukhQxSpq0ObvJyuLis9+3uS5uUvAoYBhAiuPujgf0t47+bSc3ToB1HgCiPyw12e5zKl0RvjYGClb06ID5jPzA9SwtucKrAanyAz4L0P/aQNqTpIlmhrc6ht+ObxgVq55SL4n7vn2JPGq6zllpv/aNrNzu/BnesU8VH6GWzXG29v8LrKnZwNHDW7VvoMnJ3PNCXLb19tocJLnP6/WF26WQ=="
    let data = NSData(base64EncodedString: encryptedString, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)!
    let privateKeyData = NSData(contentsOfURL: NSBundle(forClass: self.classForCoder).URLForResource("keys-private", withExtension: "pem")!)!
    do {
      let privateKey = try PrivateKey(privateKey:privateKeyData)
      let decryptedData = try privateKey.decrypt(data)
      let decryptedString = NSString(data: decryptedData, encoding: NSUTF8StringEncoding)
      XCTAssertEqual(decryptedString, "Hello World")
    } catch {
      XCTFail()
    }
  }
  
  
  func testSignAndVerify() {
    let keys = AsymmetricKeys.generateKeyPair()
    let data = "Hello World".dataUsingEncoding(NSUTF8StringEncoding)!
    do {
      let signature = try keys.privateKey.signature(data)
      XCTAssertTrue(keys.publicKey.verify(data, signature: signature))
    } catch {
      XCTFail()
    }
  }
  
  
  func testOpenSSLKeySignAndVerify() {
    let publicKeyData = NSData(contentsOfURL: NSBundle(forClass: self.classForCoder).URLForResource("keys-public", withExtension: "pem")!)!
    let privateKeyData = NSData(contentsOfURL: NSBundle(forClass: self.classForCoder).URLForResource("keys-private", withExtension: "pem")!)!
    let secretData = "Hello Me".dataUsingEncoding(NSUTF8StringEncoding)!
    do {
      let publicKey = try PublicKey(publicKey: publicKeyData)
      let privateKey = try PrivateKey(privateKey: privateKeyData)
      let signature = try privateKey.signature(secretData)
      XCTAssertTrue(publicKey.verify(secretData, signature: signature))
    } catch {
      XCTFail()
    }
  }
  
  
  func testVerifyOpenSSLSignedData() {
    let signatureString = "G2D8bXS/Rfo94JHQIS/QtYTaAPnDqJtUKGC4d5okKDBH5FlCOR9APbBzlinnrT+SxtoNJoWK49bgo2l/J9G85FSSzErJgnGFv2ZVlsVs1Pce5uf71labNc10T8mgk8wOz/i9foCGKtIU920/Xq9HOW/KRXII29yeIAdLnQiNKXV+MG6G/FWgn9TheGwkhTQWqw06igLY+Feau3pgQsPekcvYCM6skGnozJuMCSciIKvlPzHez4sYEPIqSUnWZjEHQmo3HJSAuiUyXaT9mJJ2AJKJHCK7PW5Qdh5CuXARrJt4/6KDAwqd5D+JA2GA0sK8CogPeSAn67/AA3w1H6EenA=="
    let secretData = "Hello World".dataUsingEncoding(NSUTF8StringEncoding)!
    let publicKeyData = NSData(contentsOfURL: NSBundle(forClass: self.classForCoder).URLForResource("keys-public", withExtension: "pem")!)!
    let signatureData = NSData(base64EncodedString: signatureString, options: .IgnoreUnknownCharacters)!
    do {
      let publicKey = try PublicKey(publicKey: publicKeyData)
      XCTAssertTrue(publicKey.verify(secretData, signature: signatureData))
    } catch {
      XCTFail()
    }
  }
}
