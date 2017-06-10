//
//  SymmetricKeyTests.swift
//  Keys
//
//  Created by Sean Cheng on 8/11/15.
//
//

import XCTest
import Keys


class SymmetricKeyTests: XCTestCase {
  
  func testCreateRandomSymmetricKey() {
    let key = SymmetricKey()
    print(key.cryptoKey)
		XCTAssertNotNil(key.hmacKey)
    print(key.IV)
    print(key.options)
  }
  
  
  func testCrypto() {
    let key = SymmetricKey()
    let data = "Hello World!".data(using: String.Encoding.utf8)!
    do {
      let encryptedData = try key.encrypt(data)
      let decryptedData = try key.decrypt(encryptedData)
      XCTAssertEqual(data, decryptedData)
    } catch {
      XCTFail("Cannot encrypt and decrypt data properly")
    }
  }
  
  
  func testSignature() {
    let key = SymmetricKey()
    let data = "Hello World!".data(using: String.Encoding.utf8)!
    do {
      let signature = try key.signature(data)
      let result = try key.verify(data,signature: signature)
      XCTAssertTrue(result)
    } catch {
      XCTFail("Cannot sign and verify data properly")
    }
  }
}

