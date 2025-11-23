First save Alice's public key to file: alice_public_key_for_verify

Bob to verify Alice's msg by using her public key.

cargo run -- alice.json



# prompt
```
在BobVerify这个Rust Project里头,能帮我增加这样一个功能,因为Alice会send过来一个JSON的一个文件,JSON文件里头有三个Fill,一个Fill是Message,就是对这个Message签名的Message的本体,另外一个是Signature, Signature就是Alice签的签名,还有另外一个就是Public Key,就是Alice的公Key,在Bob这个Project下面呢,就有一个文件,就是叫做Alice underscore Public Key,这里面是一个Base64 encoded Alice的公钥, 所以用那个公钥去verify Alice send过来的那个Message。

cat alice.json
{
"message": "this is a good thing",
"signature": "R0Wq/DWAoP2oETguQjJ95CoJTyxy9htcUUiMOA46iFT7P8zKq4IXonf061MsKodJssSdIEB7OgdJsSltwbyTBw==",
"public_key": "C8En2lnl9ndHbHGDSTzHznX7Z1rgeHDbieMFyimz++Y="
}

alice_public_key_for_verify
```
