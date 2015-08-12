## Keys - 三把数据加密的钥匙
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

Keys 参考了 Agilebits 公司的产品 1Password 提供的公开资料。 若想学习 1Password 的数据加密原理，请访问网站 https://support.1password.com/opvault-design/

Keys 参考了 Apple iMessage 提供的公开资料。若想学习有关 iMessage 的数据加密原理。请访问网站


## 三把 “钥匙”

Keys 由三种不同“钥匙”组成。你需要根据软件的需求，使用不同的“钥匙”加密用户的数据。
- 对称密钥 / 用于加密数据。由一个随机数据组成。适合加密存储在本地的数据。
- 非对称密钥 / 用于解密数据。由两个随机数据组成。适合加密需要在互联网上传输的数据。
- 密码 / 用于加密对称密钥。由字串符和盐（随机数据）组成。不能用于加密数据。


## 最佳实践

### 储存在本地的加密数据

用户的数据不应该直接使用密码字串符加密。当你需要加密数据时，你必须使用对称密钥加密用户的数据，再用密码加密对称密钥。 同理，当你需要解密数据时。你需要通过密码解密对称密钥，再用对称密钥解密用户的数据。

### 需要传输的加密数据

当你需要将某些加密数据传输到第三方时，你需要使用非对称密钥。你可以想象一个金库有两把钥匙，一把能够用来将黄金放进金库，一把能够用来取出黄金。当你需要传输数据时，你在本地使用其中一把钥匙加密数据后，你将另一把钥匙和数据传输到另外一个设备，另外一个设备就能够解密你的数据。

## Carthage

需要使用 Keys。 请安装 Carthage 并在 Cartfile 内加入

```
	github "remaerd/Keys"
```
