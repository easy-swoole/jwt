<?php

namespace EasySwoole\Jwt\Tests;

use EasySwoole\Jwt\Exception;
use EasySwoole\Jwt\Jwt;
use EasySwoole\Jwt\JwtObject;
use EasySwoole\Jwt\Signature;
use PHPUnit\Framework\TestCase;

/**
 * Jwt 测试
 * Class JwtTest
 * @package EasySwoole\Jwt\Tests
 */
class JwtTest extends TestCase
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
    private $prefix;
    private $other;

    protected function setUp(): void
    {
        parent::setUp();
        $this->alg     = Jwt::ALG_METHOD_HS256;
        $this->aud     = 'user';
        $this->exp     = time();
        $this->iat     = time() + 3600;
        $this->iss     = 'admin';
        $this->jti     = md5(time());
        $this->nbf     = time() + 60 * 5;
        $this->sub     = 'auth';
        $this->extData = 'extData';
        $this->other   = 'other';
        $this->prefix  = 'Bearer';
    }

    public function testJwt()
    {
        $jwtObject = Jwt::getInstance()->publish();
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
        $this->assertTrue($jwtObject->setPrefix($this->prefix) instanceof JwtObject);

        $this->assertTrue($jwtObject->getAlg() == $this->alg);
        $this->assertTrue($jwtObject->getAud() == $this->aud);
        $this->assertTrue($jwtObject->getExp() == $this->exp);
        $this->assertTrue($jwtObject->getIat() == $this->iat);
        $this->assertTrue($jwtObject->getIss() == $this->iss);
        $this->assertTrue($jwtObject->getJti() == $this->jti);
        $this->assertTrue($jwtObject->getNbf() == $this->nbf);
        $this->assertTrue($jwtObject->getSub() == $this->sub);
        $this->assertTrue($jwtObject->getData() == $this->extData);
        $this->assertTrue($jwtObject->getPrefix() == $this->prefix . ' ');
        $this->assertTrue(is_string($jwtObject->__toString()));
    }

    /**
     * @throws Exception
     */
    public function testDecode()
    {
        $jwtObject = Jwt::getInstance()->publish();
        $jwtObject->setAlg($this->alg);
        $jwtObject->setAud($this->aud);
        $jwtObject->setExp($this->exp);
        $jwtObject->setIat($this->iat);
        $jwtObject->setIss($this->iss);
        $jwtObject->setJti($this->jti);
        $jwtObject->setNbf($this->nbf);
        $jwtObject->setSub($this->sub);
        $jwtObject->setData($this->extData);
        $jwtObject->setPrefix($this->prefix);
        $token = $jwtObject->__toString();

        $jwtObject = Jwt::getInstance()->decode($token);
        $status    = $jwtObject->getStatus();
        $this->assertTrue($status === JwtObject::STATUS_OK);
        $this->assertTrue($jwtObject->getAlg() == $this->alg);
        $this->assertTrue($jwtObject->getAud() == $this->aud);
        $this->assertTrue($jwtObject->getExp() == $this->exp);
        $this->assertTrue($jwtObject->getIat() == $this->iat);
        $this->assertTrue($jwtObject->getIss() == $this->iss);
        $this->assertTrue($jwtObject->getJti() == $this->jti);
        $this->assertTrue($jwtObject->getNbf() == $this->nbf);
        $this->assertTrue($jwtObject->getSub() == $this->sub);
        $this->assertTrue($jwtObject->getData() == $this->extData);
        $this->assertTrue($jwtObject->getPrefix() == $this->prefix);
    }


    /**
     *  token过期
     * @throws Exception
     */
    public function testExpiredToken()
    {
        $jwtObject = Jwt::getInstance()->publish();
        $jwtObject->setExp(time() - 3600);
        $status = Jwt::getInstance()->decode($jwtObject->__toString())->getStatus();
        $this->assertTrue($status === JwtObject::STATUS_EXPIRED);
    }

    /**
     * 修改token参数
     * @throws Exception
     */
    public function testChangeToken()
    {
        $jwtObject = Jwt::getInstance()->publish();
        $jwt       = $jwtObject->__toString();

        // 把签名解释出来，然修改，然后再放回去
        $jwt = substr_replace($jwt, mt_rand(1000, 9999), -4, 4);

        $status = Jwt::getInstance()->decode($jwt)->getStatus();
        $this->assertTrue($status === JwtObject::STATUS_SIGNATURE_ERROR);
    }

    /**
     *  通过第三方生成的token, 用于验证payload自定义参数
     * header: {
     *   "alg": "HS256",
     *   "typ": "JWT"
     * }
     * payload: {
     *  "exp": "1906893573",
     *  "other": "other"
     * }
     * signature: HMACSHA256(
     *  base64UrlEncode(header) + "." +
     *  base64UrlEncode(payload),
     *  easyswoole
     * )
     * @throws Exception
     */
    public function testOtherInfo()
    {
        $token     = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxOTA2ODkzNTczIiwib3RoZXIiOiJvdGhlciJ9.eDiVODe_LoARtYU8968tJYtQz3nZkae8y6QZv4QtLT4';
        $jwtObject = Jwt::getInstance()->setSecretKey('easyswoole')->decode($token);
        $this->assertTrue($jwtObject->getStatus() === JwtObject::STATUS_OK);
        $this->assertTrue($jwtObject->other === $this->other);
    }

    /**
     * https://jwt.io/ 通过第三方生成的签名与es生成的签名做对比
     * header: {
     * "alg": "HS256",
     * "typ": "JWT"
     * }
     * payload: {
     * "exp": "1906893573",
     * }
     * signature: HMACSHA256(
     * base64UrlEncode(header) + "." +
     * base64UrlEncode(payload),
     * easyswoole
     * )
     */
    public function testSignature()
    {
        $token     = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDY4OTM1NzN9.ngWBkKeKiOMjRQpi5rvY5xRf0yZzvx_NSfi5msZCRmA';
        $token     = explode('.', $token);
        $signature = (new Signature([
            'secretKey' => 'easyswoole',
            'header' => $token[0],
            'payload' => $token[1],
            'alg' => $this->alg
        ]))->__toString();
        $this->assertTrue($signature === $token[2]);
    }

    public function testException()
    {
        $this->expectException(Exception::class);
        Jwt::getInstance()->decode(mt_rand());
    }
}
