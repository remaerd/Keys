[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/remaerd/Keys)
[![Version](https://img.shields.io/github/release/soffes/Crypto.svg)](https://github.com/remaerd/Keys/releases)
[![License](https://img.shields.io/pypi/l/Django.svg)](https://github.com/remaerd/Keys/blob/master/LICENSE)


# Keys - 三把数据加密的钥匙
*Please help me translate the README documentation. Thanks!*


## 干嘛用

```swift
	let password = Password("Secret")
	let key = SymmetricKey()
	password.encrypt(data)
	let data = "Hello World!".dataUsingEncoding(NSUTF8StringEncoding)!
	let encryptedData = key.encrypt(data)
	let decryptedData = key.decrypt(encryptedData)
	print(decryptedData) // "Hello World!"
```

Keys 是一个没有学习曲线的数据加密开源框架。 Keys 简化了 CommonCrypto 内复杂的参数和接口，帮助你有效地实现数据加密解密功能。

想深入了解软件如何加密你的数据，我推荐阅读 1Password / iMessage 这两个软件的数据加密原理的相关文档。你亦可以直接使用 Keys 提供的 API 接口， Keys 依据数据加密学的 Best Practice 设计。

- 1Password https://support.1password.com/opvault-design/
- iMessage https://www.apple.com/business/docs/iOS_Security_Guide.pdf

## 三把 “钥匙”

Keys 由三种不同“钥匙”组成。你需要根据软件的需求，使用不同的“钥匙”加密用户的数据。
- 对称密钥 / 用于加密数据。由一个随机数据组成。适合加密存储在本地的数据。
- 非对称密钥 / 用于加密数据。由两个随机数据组成。适合加密需要在互联网上传输的数据。
- 密码 / 用于加密对称密钥。由字串符和盐（随机数据）组成。不能用于加密数据。


## 最佳实践

### Carthage

需要使用 Keys。 请安装 Carthage 并在 Cartfile 内加入

```
	github "remaerd/Keys"
```

### 储存在本地的加密数据

用户的数据不应该直接使用密码字串符加密。当你需要加密数据时，你必须使用对称密钥加密用户的数据，再用密码加密对称密钥。 同理，当你需要解密数据时。你需要通过密码解密对称密钥，再用对称密钥解密用户的数据。

#### 新建密码

```swift
	let password = Password("Hello")
	let salt = password.salt // 盐
	let rounds = password.rounds // Rounds
	let data = password.data // 由密码和盐计算出来的密钥
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
	let keys = AsymmetricKeys()
	let cryptoKeys = keys.keys // 加密/解密用的一对密钥
	let validationKeys = key.validationKeys // 验证数据用的一对密钥
```

每次生成新的非对称密钥。将会同时生成两对密钥。四个钥匙分别负责加密，解密，获得数据签名，验证数据。当传输数据时，你需要将加密后的数据，以及 cryptoKeys 的 publicKey， validationKeys.publicKey 同时发送到数据接收者的设备。

#### CommonCrypto 秘钥

使用 ｀｀｀AsymmetricKeys()｀｀｀， Keys 会生成一对由 CommonCrypto 生成的 RSA 秘钥，你可以通过这对秘钥分别加密／解密数据。

由 ```AsymmetricKeys``` 生成的秘钥适用于 iOS 设备之间的加密数据传输。若需要在多个设备端（服务器，Android 等），请使用 OpenSSL 生成的 RSA 秘钥。

```swift
	let data = "Hello World!".dataUsingEncoding(NSUTF8StringEncoding)!
	let keys = AsymmetricKeys()
	let publicKey = keys.keys.publicKey
	let privateKey = keys.keys.privateKey
	do {
		let encryptedData = try publicKey.encrypt(data)
		let decryptedData = try privateKey.decrypt(data)
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
		let encryptedData = try publicKey.encrypt(data)
		let decryptedData = try privateKey.decrypt(data)
		print(NSString(data: decryptedData, encoding: NSUTF8StringEncoding))
		// Hello World
	} catch {
		print("Cannot decrypt data")
	}
```

