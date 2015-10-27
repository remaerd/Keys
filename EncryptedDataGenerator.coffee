ursa 	= require('ursa')
fs 		= require('fs')

publicKey		= ursa.createPublicKey(fs.readFileSync('./Tests/keys-public.pem'))
privateKey	= ursa.createPrivateKey(fs.readFileSync('./Tests/keys-private.pem'))

signature		= privateKey.hashAndSign('sha1','Hello World','utf8','base64')

console.log(signature)