ursa 	= require('ursa')
fs 		= require('fs')

publicKey		= ursa.createPublicKey(fs.readFileSync('./keys-public.pem'))
privateKey	= ursa.createPublicKey(fs.readFileSync('./keys-private.pem'))
secret 			= publicKey.encrypt('Hello World')

console.log(secret)
console.log(privateKey.decrypt(secret, 'base64', 'utf8'))