import * as crypto from 'crypto'
import * as querystring from 'querystring'
import * as zlib from 'zlib'

type Dic<T> = { [key: string]: T }
type Session = { [key: string]: string | string[] }

const SESSION_SECRET = 'SESSION_SECRET_FOR_COA_FRAMEWORK'
const HMAC_MD5_ID_SECRET = 'HMAC_MD5_ID_SECRET_FOR_COA_FRAMEWORK'

export default new class {

  // 计算sha1
  sha1 (data: crypto.BinaryLike, digest: crypto.BinaryToTextEncoding = 'hex') {
    return crypto.createHash('sha1').update(data).digest(digest)
  }

  // 计算md5
  md5 (data: crypto.BinaryLike, digest: crypto.BinaryToTextEncoding = 'hex') {
    return crypto.createHash('md5').update(data).digest(digest)
  }

  // 计算id32算法（自命名），计算一个或多个字符串的md5值，保证返回值长度为32位十六进制格式
  id32 (...values: string[]) {
    const value = JSON.stringify(values)
    return crypto.createHmac('md5', HMAC_MD5_ID_SECRET).update(value).digest('hex')
  }

  // 计算id32算法，并将返回值转换为25位三十六进制格式
  id25 (...values: string[]) {
    const id32 = this.id32(...values)
    const result = 0xffffffffffffffffffffffffffffffffn + BigInt('0x' + id32)
    return result.toString(36)
  }

  // 计算sha1_hmac
  sha1_hmac (str: crypto.BinaryLike, key: string, digest: crypto.BinaryToTextEncoding = 'hex') {
    return crypto.createHmac('sha1', key).update(str).digest(digest)
  }

  // 计算sha256_hmac
  sha256_hmac (str: crypto.BinaryLike, key: string, digest: crypto.BinaryToTextEncoding = 'hex') {
    return crypto.createHmac('sha256', key).update(str).digest(digest)
  }

  // 计算rsa_sha256
  rsa_sha256 (data: any, key: string, format: crypto.BinaryToTextEncoding = 'base64') {
    return crypto.createSign('RSA-SHA256').update(data).sign(key, format)
  }

  // base64 encode
  base64_encode (str: string) {
    return Buffer.from(str).toString('base64')
  }

  // base64 decode
  base64_decode (base64: string) {
    return Buffer.from(base64, 'base64').toString()
  }

  // aes 加密
  aes_encode (data: any, key = '', iv = '') {
    if (!data) return ''
    let clearEncoding: crypto.Encoding = 'utf8', cipherEncoding: crypto.BinaryToTextEncoding = 'base64', cipherChunks = [] as string[]
    let cipher = crypto.createCipheriv('aes-256-ecb', key, iv)
    cipher.setAutoPadding(true)
    cipherChunks.push(cipher.update(data, clearEncoding, cipherEncoding))
    cipherChunks.push(cipher.final(cipherEncoding))
    return cipherChunks.join('')
  }

  // aes 解密
  aes_decode (data: any, key = '', iv = '') {
    if (!data) return ''
    let clearEncoding: crypto.Encoding = 'utf8', cipherEncoding: crypto.BinaryToTextEncoding = 'base64', cipherChunks = [] as string[]
    let decipher = crypto.createDecipheriv('aes-256-ecb', key, iv)
    decipher.setAutoPadding(true)
    cipherChunks.push(decipher.update(data, cipherEncoding, clearEncoding))
    cipherChunks.push(decipher.final(clearEncoding))
    return cipherChunks.join('')
  }

  // 转换base64数据 / 转为 _ ， + 转为 - , 去除 =
  base64_compress (base64_string: string) {
    const replacer = { '/': '_', '+': '-', '=': '' } as Dic<string>
    return base64_string.replace(/[\/+=]/g, x => replacer[x])
  }

  // 反转换base64
  base64_decompress (base64_string: string) {
    const replacer = { '_': '/', '-': '+' } as Dic<string>
    return base64_string.replace(/[_-]/g, x => replacer[x])
  }

  // 通过brotli算法对字符串进行压缩，返回base64格式
  brotli_compress (raw_string: string) {
    const base64 = zlib.brotliCompressSync(Buffer.from(raw_string, 'utf8')).toString('base64')
    return this.base64_compress(base64)
  }

  // 解压缩字符串的brotli加密
  brotli_decompress (encode_string: string) {
    try {
      const base64 = this.base64_decompress(encode_string)
      return zlib.brotliDecompressSync(Buffer.from(base64, 'base64')).toString('utf8')
    } catch (e) {
      return ''
    }
  }

  // session数据（一个普通对象）加密成一个简短的字符串
  session_encode (info: Session, ms: number) {
    const value = querystring.stringify(info)
    const expire = (Date.now() + ms).toString().substr(0, 10)
    const sign = this.sha1_hmac(expire + value, SESSION_SECRET, 'base64').substr(0, 6)
    return this.brotli_compress(sign + expire + value)
  }

  // session字符串数据解密
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