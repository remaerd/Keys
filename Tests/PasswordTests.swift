//
//  PasswordTests.swift
//  Tests
//
//  Created by Sean Cheng on 8/11/15.
//
//

import XCTest
@testable import Keys


class PasswordTests: XCTestCase {
  
  func testCreatePassword() {
    do {
      let password = try Password(password: "HelloWorld")
      print(password)
    } catch {
      XCTFail("Cannot create password")
    }
  }
  
  
  func testRandomPassword() {
    let password = Password.new()
    print(password)
//    XCTAssertTrue(password != nil, "Cannot create random password")
  }
  
  
  func testPasswordSimilarity() {
    do {
      let password = try Password(password:"HelloWorld")
      let newPassword = try Password(password:"HelloWorld", salt:password.salt, roundCount: password.rounds)
      print(password.data.base64EncodedString())
      print(newPassword.data.base64EncodedString())
      XCTAssertEqual(password.data, newPassword.data)
    } catch {
      XCTFail("Cannot create password")
    }
  }
  
  
  func testPasswordUnique() {
    do {
      let password = try Password(password:"HelloWorld")
      let newPassword = try Password(password:"HelloWorld")
      print(password.data.base64EncodedString())
      print(newPassword.data.base64EncodedString())
      XCTAssertNotEqual(password.data, newPassword.data)
    } catch {
      XCTFail("Cannot create password")
    }
  }
  
  
  func testWrapSymmetricKey() {
    do {
      let key = SymmetricKey()
      
      var password = try Password(password:"Hello")
      let encryptedKeyData = try password.encrypt(key)
      let decryptedKey = try password.decrypt(encryptedKeyData.key, IV: encryptedKeyData.IV)
      XCTAssertTrue(decryptedKey.cryptoKey == key.cryptoKey, "Invalid wrapping symmetric key")
    } catch {
      XCTFail("Cannot wrap symmetric key")
    }
  }
}
