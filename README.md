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

`Keys` is design to work with *Best practice* encryption only. If you are not familar with Master Key encryption and Public Key cncryption, Please read the following materials to learn about how iMessage and 1Password encrypt your data.

- 1Password https://support.1password.com/opvault-design/
- iMessage https://www.apple.com/business/docs/iOS_Security_Guide.pdf

## Three type of Keys

There're three kind of keys in the framwork. You can use them according to what you are encrypting.

- *Symmetric Key* for encrypting / decrypting local data saving in the same device
- *Asymmetric Keys* for encrypting  / decrypting data need to be transfers between devices or servers.
- *Password* for encrypting / decrypting Symmetric Keys


## Best practice

### Carthage

Please intall [Carthage](https://github.com/carthage/carthage) then insert the following code into your `Cartfile`.

```
	github "remaerd/Keys"
```

### Encrypting local data

You must *not* encrypt data with user's `String` password. When you need to encrypt a piece of data. You need to create a `SymmetricKey` object to encrypt the data. Then create a `Password` object from user's `String` password. Finally, encrypt the `SymmetricKey` object with the `Password`. Encrypting your users's data with `String` password is dangerous and naïve, please never do this.

#### Creating a `Password` object

```swift
	let password = Password("Hello")
	let salt = password.salt
	let rounds = password.rounds
	let data = password.data
```

每次新建密码会自动生成一个随机盐和 Round 值。当你使用相同的密码但不同的盐 ／ Round 值生成密码后，新的 Password 不能够解密之前用 Password 加密过的数据。
你不应该将用户的密码明文保存到本地，但你需要将盐和 Rounds 保存到本地。当创建密码时，你应该重新问用户获取密码，再用盐和 Rounds 重建密码。

#### 新建对称密钥

```swift
	let key = SymmetricKey()
	let encryptionKey = key.cryptoKey // 加密用的密钥
	let iv = key.IV // IV
	let hmacKey = key.hmacKey // 生成 MAC （ 数据验证码 Message Authentication Code） 用的密钥
```

每次新建对称密钥会自动生成一个随机 IV 值和 验证数据用的 HMAC。当你需要保留密钥时，你需要同时在本地存储 cryptoKey，IV，和 hmac。

#### 加密数据

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

#### 解密数据

```swift
	let key = SymmetricKey(key: keyData, hmacKey: hmacData, IV: IVData)
	do {
		let decryptedData = try key.decrypt(data)
		print(decryptedData)
	} catch {
		print("Cannot decrypt data")
	}
```

### 需要传输的加密数据

当你需要将某些加密数据传输到第三方时，你需要使用非对称密钥。你可以想象一个金库有两把钥匙，一把能够用来将黄金放进金库，一把能够用来取出黄金。当你需要传输数据时，你在本地使用其中一把钥匙加密数据后，你将另一把钥匙和数据传输到另外一个设备，另外一个设备就能够解密你的数据。

#### 新建非对称密钥

```swift
	let keys = AsymmetricKeys.generateKeyPair()
	let publicKey = keys.publicKey // 加密/解密用的一对密钥
	let privateKey = key.privateKey // 验证数据用的一对密钥
```

每次生成新的非对称密钥，将会获得一对密钥，分别负责加密，解密数据。你亦可以使用 ```AsymmetricKeys.generateKeyPair()``` 同时生成两对秘钥，分别用于加密／解密／签名／验证数据。

#### CommonCrypto 秘钥

使用 ```AsymmetricKeys.generateKeyPair()```， Keys 会生成一对由 CommonCrypto 生成的 RSA 秘钥，你可以通过这对秘钥分别加密／解密数据。

由 ```AsymmetricKeys.generateKeyPair()``` 生成的秘钥适用于 iOS 设备之间的加密数据传输。若需要在多个设备端（服务器，Android 等），请使用 OpenSSL 生成的 RSA 秘钥。

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

#### OpenSSL 秘钥

通过 OpenSSL，你可以在服务器端生成 RSA 秘钥，用 PublicKey 加密数据后，将 PrivateKey，以及加密的数据传输到用户客户端。通过以下两段 Terminal.app 代码，你可以生成一对 RSA 秘钥。

```bash
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -pubout -out public.pub 
```

Swift 客户端获得加密数据和 PrivateKey 后，即可解密数据。

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

