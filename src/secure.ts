import * as crypto from 'crypto'
import * as querystring from 'querystring'
import * as zlib from 'zlib'

type Dic<T> = { [key: string]: T }
type Session = { [key: string]: string | string[] }

const SESSION_SECRET = 'SESSION_SECRET_FOR_COA_FRAMEWORK'

export default new class {

  sha1 (data: crypto.BinaryLike, digest: crypto.HexBase64Latin1Encoding = 'hex') {
    return crypto.createHash('sha1').update(data).digest(digest)
  }

  md5 (data: crypto.BinaryLike, digest: crypto.HexBase64Latin1Encoding = 'hex') {
    return crypto.createHash('md5').update(data).digest(digest)
  }

  sha1_hmac (str: crypto.BinaryLike, key: string, digest: crypto.HexBase64Latin1Encoding = 'hex') {
    return crypto.createHmac('sha1', key).update(str).digest(digest)
  }

  sha256_hmac (str: crypto.BinaryLike, key: string, digest: crypto.HexBase64Latin1Encoding = 'hex') {
    return crypto.createHmac('sha256', key).update(str).digest(digest)
  }

  rsa_sha256 (data: any, key: string, format: crypto.HexBase64Latin1Encoding = 'base64') {
    return crypto.createSign('RSA-SHA256').update(data).sign(key, format)
  }

  base64_encode (str: string) {
    return Buffer.from(str).toString('base64')
  }

  base64_decode (base64: string) {
    return Buffer.from(base64, 'base64').toString()
  }

  aes_encode (data: any, key = '', iv = '') {
    if (!data) return ''
    let clearEncoding: crypto.Utf8AsciiBinaryEncoding = 'utf8', cipherEncoding: crypto.HexBase64BinaryEncoding = 'base64', cipherChunks = [] as string[]
    let cipher = crypto.createCipheriv('aes-256-ecb', key, iv)
    cipher.setAutoPadding(true)
    cipherChunks.push(cipher.update(data, clearEncoding, cipherEncoding))
    cipherChunks.push(cipher.final(cipherEncoding))
    return cipherChunks.join('')
  }

  aes_decode (data: any, key = '', iv = '') {
    if (!data) return ''
    let clearEncoding: crypto.Utf8AsciiBinaryEncoding = 'utf8', cipherEncoding: crypto.HexBase64BinaryEncoding = 'base64', cipherChunks = [] as string[]
    let decipher = crypto.createDecipheriv('aes-256-ecb', key, iv)
    decipher.setAutoPadding(true)
    cipherChunks.push(decipher.update(data, cipherEncoding, clearEncoding))
    cipherChunks.push(decipher.final(clearEncoding))
    return cipherChunks.join('')
  }

  base64_compress (base64_string: string) {
    const replacer = { '/': '_', '+': '-', '=': '' } as Dic<string>
    return base64_string.replace(/[\/+=]/g, x => replacer[x])
  }

  base64_decompress (base64_string: string) {
    const replacer = { '_': '/', '-': '+' } as Dic<string>
    return base64_string.replace(/[_-]/g, x => replacer[x])
  }

  brotli_compress (raw_string: string) {
    const base64 = zlib.brotliCompressSync(Buffer.from(raw_string, 'utf8')).toString('base64')
    return this.base64_compress(base64)
  }

  brotli_decompress (encode_string: string) {
    try {
      const base64 = this.base64_decompress(encode_string)
      return zlib.brotliDecompressSync(Buffer.from(base64, 'base64')).toString('utf8')
    } catch (e) {
      return ''
    }
  }

  session_encode (info: Session, ms: number) {
    const value = querystring.stringify(info)
    const expire = (Date.now() + ms).toString().substr(0, 10)
    const sign = this.sha1_hmac(expire + value, SESSION_SECRET, 'base64').substr(0, 6)
    return this.brotli_compress(sign + expire + value)
  }

  session_decode (str: string) {

    str = this.brotli_decompress(str)

    if (!str)
      return null

    const expire = parseInt(str.substr(6, 10)) || 0

    if (expire * 1000 < Date.now())
      return null

    const value = str.substr(16)
    const sign = str.substr(0, 6)
    const real_sign = this.sha1_hmac(expire + value, SESSION_SECRET, 'base64').substr(0, 6)

    if (sign !== real_sign)
      return null

    return querystring.parse(value) as Session

  }
}