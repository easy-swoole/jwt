<?php
/**
 * This file is part of EasySwoole.
 *
 * @link https://www.easyswoole.com
 * @document https://www.easyswoole.com
 * @contact https://www.easyswoole.com/Preface/contact.html
 * @license https://github.com/easy-swoole/easyswoole/blob/3.x/LICENSE
 */

namespace EasySwoole\Jwt\Tests;

use EasySwoole\Jwt\Encryption;
use EasySwoole\Jwt\Exception;
use EasySwoole\Jwt\Jwt;
use EasySwoole\Jwt\JwtObject;
use EasySwoole\Jwt\Signature;
use PHPUnit\Framework\TestCase;

/**
 * RS256 签名 Jwt测试
 * Test Jwt for RS256 signature
 *
 * Class JwtTest
 * @package EasySwoole\Jwt\Tests
 */
class RS256JwtTest extends TestCase
{
    private $alg;
    private $aud;
    private $exp;
    private $iat;
    private $iss;
    private $jti;
    private $nbf;
    private $sub;
    private $extData;
    private $other;
    private $publicKey;
    private $privateKey;

    protected function setUp(): void
    {
        parent::setUp();
        $this->alg = Jwt::ALG_METHOD_RS256;
        $this->aud = 'user';
        $this->exp = time();
        $this->iat = time() + 3600;
        $this->iss = 'admin';
        $this->jti = md5(time());
        $this->nbf = time() + 60 * 5;
        $this->sub = 'auth';
        $this->extData = 'extData';
        $this->other = 'other';

        // 解密公钥
        // PUBLIC_KEY for decrypt
        $this->publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----
EOD;
        // 加密私钥
        // PRIVATE_KEY for encrypt
        $this->privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----
EOD;

    }

    public function testJwt()
    {
        // 在发布之后，你得到 $jwtObject 对象，然后可以进行相关配置。
        // after published, you get the jwtObject, then you can configure it.
        $jwtObject = Jwt::getInstance()->setSecretKey($this->privateKey)->publish();

        $this->assertTrue($jwtObject instanceof JwtObject);
        $this->assertTrue($jwtObject->setAlg($this->alg) instanceof JwtObject);
        $this->assertTrue($jwtObject->setAud($this->aud) instanceof JwtObject);
        $this->assertTrue($jwtObject->setExp($this->exp) instanceof JwtObject);
        $this->assertTrue($jwtObject->setIat($this->iat) instanceof JwtObject);
        $this->assertTrue($jwtObject->setIss($this->iss) instanceof JwtObject);
        $this->assertTrue($jwtObject->setJti($this->jti) instanceof JwtObject);
        $this->assertTrue($jwtObject->setNbf($this->nbf) instanceof JwtObject);
        $this->assertTrue($jwtObject->setSub($this->sub) instanceof JwtObject);
        $this->assertTrue($jwtObject->setData($this->extData) instanceof JwtObject);

        $this->assertTrue($jwtObject->getAlg() == $this->alg);
        $this->assertTrue($jwtObject->getAud() == $this->aud);
        $this->assertTrue($jwtObject->getExp() == $this->exp);
        $this->assertTrue($jwtObject->getIat() == $this->iat);
        $this->assertTrue($jwtObject->getIss() == $this->iss);
        $this->assertTrue($jwtObject->getJti() == $this->jti);
        $this->assertTrue($jwtObject->getNbf() == $this->nbf);
        $this->assertTrue($jwtObject->getSub() == $this->sub);
        $this->assertTrue($jwtObject->getData() == $this->extData);
        $this->assertTrue($jwtObject->getSecretKey() == $this->privateKey);

        // 断言生成的 jwt 是否为字符串
        // Asserts whether the generated JWT is a string.
        $this->assertTrue(is_string($jwtObject->__toString()));
    }

    public function testDecode()
    {
        $jwtObject = Jwt::getInstance()->setSecretKey($this->privateKey)->publish();

        $jwtObject->setAlg($this->alg);
        $jwtObject->setAud($this->aud);
        $jwtObject->setExp($this->exp);
        $jwtObject->setIat($this->iat);
        $jwtObject->setIss($this->iss);
        $jwtObject->setJti($this->jti);
        $jwtObject->setNbf($this->nbf);
        $jwtObject->setSub($this->sub);
        $jwtObject->setData($this->extData);

        // 生成 jwt
        // Generate jwt
        $token = $jwtObject->__toString();

        $jwtObject = Jwt::getInstance()->setAlg($this->alg)->setSecretKey($this->publicKey)->decode($token);

        // 断言解码出来的 jwt 的参数是否一致
        // Asserts whether the parameters of the decoded JWT are consistent
        $this->assertTrue($jwtObject->getStatus() === JwtObject::STATUS_OK);
        $this->assertTrue($jwtObject->getAlg() == $this->alg);
        $this->assertTrue($jwtObject->getAud() == $this->aud);
        $this->assertTrue($jwtObject->getExp() == $this->exp);
        $this->assertTrue($jwtObject->getIat() == $this->iat);
        $this->assertTrue($jwtObject->getIss() == $this->iss);
        $this->assertTrue($jwtObject->getJti() == $this->jti);
        $this->assertTrue($jwtObject->getNbf() == $this->nbf);
        $this->assertTrue($jwtObject->getSub() == $this->sub);
        $this->assertTrue($jwtObject->getData() == $this->extData);
        $this->assertTrue($jwtObject->getSecretKey() == $this->publicKey);

        $jwtObject = Jwt::getInstance()->setSecretKey($this->privateKey)->publish();
        $jwtObject->setExp(time() - 3600)->setAlg($this->alg);
        $token = $jwtObject->__toString();
        $decryptRet = Jwt::getInstance()->setSecretKey($this->publicKey)->setAlg($this->alg)->decode($token);

        $this->assertTrue($decryptRet->getStatus() === JwtObject::STATUS_EXPIRED);

        $jwtObject = Jwt::getInstance()->setSecretKey($this->privateKey)->publish();
        $jwt = $jwtObject->__toString();

        // 把签名解释出来，然修改，然后再放回去
        // Explain the signature, modify it and put it back.
        $jwt = substr_replace($jwt, mt_rand(1000, 9999), -4, 4);

        $status = Jwt::getInstance()->setAlg($this->alg)->setSecretKey($this->publicKey)->decode($jwt)->getStatus();
        $this->assertTrue($status === JwtObject::STATUS_SIGNATURE_ERROR);
    }

    public function testOtherInfo()
    {
        // 通过第三方网站 http://jwt.io 生成的 token, 用于验证 payload 自定义参数
        // Through the third party website http://jwt.io The generated token is used to verify the payload custom parameters.
        //header: {
        //  "alg": "RS256",
        //  "typ": "JWT"
        //}
        //payload: {
        //  "sub": "1234567890",
        //  "name": "John Doe",
        //  "admin": true,
        //  "iat": 1516239022,
        //}
        //signature: RSASHA256(
        //  base64UrlEncode(header) + "." +
        //  base64UrlEncode(payload),
        //  PRIVATE_KEY
        // )
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA';

        // 使用 PUBLIC_KEY 公钥进行解码
        $jwtObject = Jwt::getInstance()->setAlg($this->alg)->setSecretKey($this->publicKey)->decode($token);

        $this->assertTrue($jwtObject->getAlg() === $this->alg);
        $this->assertTrue($jwtObject->getSub() === '1234567890');
        $this->assertTrue($jwtObject->name === 'John Doe');
        $this->assertTrue($jwtObject->admin === true);
        $this->assertTrue($jwtObject->getIat() === 1516239022);
        $this->assertTrue($jwtObject->getStatus() === JwtObject::STATUS_OK);
    }

    public function testSignature()
    {
        // https://jwt.io/ 通过第三方生成的签名与es生成的签名做对比
        //header: {
        //  "alg": "HS256",
        //  "typ": "JWT"
        //}
        //payload: {
        //  "exp": "1906893573",
        //}
        //signature: HMACSHA256(
        //  base64UrlEncode(header) + "." +
        //  base64UrlEncode(payload),
        //  easyswoole
        // )
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA';
        $token = explode('.', $token);
        $signature = (new Signature([
            'secretKey' => $this->privateKey,
            'header' => $token[0],
            'payload' => $token[1],
            'alg' => $this->alg
        ]))->__toString();
        $this->assertTrue($signature === $token[2]);
    }

    /**
     * @expectedException \EasySwoole\Jwt\Exception
     */
    public function testException()
    {
        $this->expectException(Exception::class);
        Jwt::getInstance()->setAlg($this->alg)->setSecretKey($this->publicKey)->decode(mt_rand());
    }
}
