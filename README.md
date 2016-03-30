[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/remaerd/Keys)
[![Version](https://img.shields.io/github/release/soffes/Crypto.svg)](https://github.com/remaerd/Keys/releases)
[![License](https://img.shields.io/pypi/l/Django.svg)](https://github.com/remaerd/Keys/blob/master/LICENSE)


# Keys - Keys of data encryption
[中文介绍](https://github.com/remaerd/Keys/blob/master/README-CHINESE.MD)

## Example

```swift
	let password = Password("Secret")
	let key = SymmetricKey()
	password.encrypt(data)
	let data = "Hello World!".dataUsingEncoding(NSUTF8StringEncoding)!
	let encryptedData = key.encrypt(data)
	let decryptedData = key.decrypt(encryptedData)
	print(decryptedData) // "Hello World!"
```

`Keys` is a data encryption framework for iOS / OS X。It's simplifies the most difficult parts of CommonCrypto, so you don't have to deal with those head stretching interfaces by your own.

`Keys` is design to work with **Best practice encryption only**. If you are not familar with Master Key encryption and Public Key cncryption, Please read the following materials to learn about how iMessage and 1Password encrypt your data.

- 1Password https://support.1password.com/opvault-design/
- iMessage https://www.apple.com/business/docs/iOS_Security_Guide.pdf

## Three type of Keys

There're three kind of keys in the framwork. You can use them according to what you are encrypting.

- **Symmetric Key** for encrypting / decrypting local data saving in the same device
- **Asymmetric Keys** for encrypting  / decrypting data need to be transfers between devices or servers.
- **Password** for encrypting / decrypting Symmetric Keys


## Best practice

### Carthage

Please intall [Carthage](https://github.com/carthage/carthage) then insert the following code into your `Cartfile`.

```
	github "remaerd/Keys"
```

### Encrypting local data

You must **NOT** encrypt data with user's `String` password. When you need to encrypt a piece of data. You need to create a `SymmetricKey` object to encrypt the data. Then create a `Password` object from user's `String` password. Finally, encrypt the `SymmetricKey` object with the `Password`. Encrypting your users's data with `String` password is dangerous and naïve, please never do this.

#### Creating `Password` object

```swift
	let password = Password("Hello")
	let salt = password.salt
	let rounds = password.rounds
	let data = password.data
```

When you create a new `Password` object with `String`. A random `salt` and `rounds` number will be generated with it.
You need to save the `salt` and `rounds` data locally, or you will create different `Password` object with the same `String`.

Do **NOT** save the `password.data` locally, or hackers will decrypt users' data by decrypting other encryption keys without password.

#### Creating `SymmetricKey` object

```swift
	let key = SymmetricKey()
	let encryptionKey = key.cryptoKey
	let iv = key.IV
	let hmacKey = key.hmacKey
```

When you are encrypting local data. You will need a `SymmetricKey` object to encrypt your data. Random Data will be generate safely, and you need to save the `cryptoKey`, `IV` and `hmacKey` of a `SymmetricKey` if you need to use the same `SymmetricKey` later.

#### Encrypting data

```swift
	let key = SymmetricKey()
	let data = "Hello World!".dataUsingEncoding(NSUTF8StringEncoding)!
	do {
		let encryptedData = try key.encrypt(data)
		print(encryptedData)
	} catch {
		print("Cannot encrypt data")
	}
```

#### Decrypting data

```swift
	let key = SymmetricKey(key: keyData, hmacKey: hmacData, IV: IVData)
	do {
		let decryptedData = try key.decrypt(data)
		print(decryptedData)
	} catch {
		print("Cannot decrypt data")
	}
```

### Encrypting data between devices / servers

When you need to encrypt data between devices, 'AsymmetricKeys' is the only option. Imagine there're two keys for one safe. You open the safe with a key and put golds into it. And you give a different key to someone you trust, so he can open the safe with a different key, but he can't put golds into your safe.

#### Creating `AsymmetricKeys` object

```swift
	let keys = AsymmetricKeys.generateKeyPair()
	let publicKey = keys.publicKey
	let privateKey = key.privateKey
```

When your create a pair of `AsymmetricKeys`, a `publicKey` and a `privateKey` will be generated. So you can encrypt your data with `publicKey` and decrypt the data with `privateKey`.

It's a good practice to generate two pair of `AsymmetricKeys`, so you can encrypt / decrypt / sign / validate your data with these four keys.

#### CommonCrypto vs. OpenSSL

If you use ```AsymmetricKeys.generateKeyPair()``` to generate `AsymmetricKeys`. those keys only works between iOS devices. If you need to use those keys between servers or Android devices. you need to use **OpenSSL** to create RSA Asymmetric Keys.

To encrypt iOS devices' data, do this:

```swift
	let data = "Hello World!".dataUsingEncoding(NSUTF8StringEncoding)!
	let keys = AsymmetricKeys.generateKeyPair()
	let publicKey = keys.publicKey
	let privateKey = keys.privateKey
	do {
		let encryptedData = try privateKey.encrypt(data)
		let decryptedData = try publicKey.decrypt(data)
		print(NSString(data: decryptedData, encoding: NSUTF8StringEncoding))
		// Hello World
	} catch {
		print("Cannot encrypt data")
	}
```

If you need to transfer encrypted between iOS Device and your servers. Generate RSA keys like this with the terminal.app

```bash
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -pubout -out public.pub 
```

The iOS Client get the Public Key and encrypted data. So you can decrypt the data with the public key.

```swift
	let data = "Hello World!".dataUsingEncoding(NSUTF8StringEncoding)!
	let publicKeyData = NSData(contentsOfURL: NSBundle.mainBundle().URLForResource("keys-public", withExtension: "pem")!)!
  let privateKeyData = NSData(contentsOfURL: NSBundle.mainBundle().URLForResource("keys-private", withExtension: "pem")!)!
	do {
		let publicKey = try PublicKey(publicKey:privateKeyData)
		let privateKey = try PrivateKey(privateKey:privateKeyData)
		let encryptedData = try privateKey.encrypt(data)
		let decryptedData = try publicKey.decrypt(encryptedData)
		print(NSString(data: decryptedData, encoding: NSUTF8StringEncoding))
		// Hello World
	} catch {
		print("Cannot decrypt data")
	}
```

