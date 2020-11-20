<?php
/**
 * @CreateTime:   2020/11/18 10:16 下午
 * @Author:       huizhang  <2788828128@qq.com>
 * @Copyright:    copyright(2020) Easyswoole all rights reserved
 * @Description:  签名生成
 */
namespace EasySwoole\Jwt;

use EasySwoole\Component\Singleton;
use EasySwoole\Spl\SplBean;

class Signature extends SplBean
{

    protected $secretKey;
    protected $header;
    protected $payload;
    protected $alg;

    public function __toString()
    {
        $content = $this->header . '.' . $this->payload;

        switch ($this->alg){
            case Jwt::ALG_METHOD_HMACSHA256:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    hash_hmac('sha256', $content, $this->secretKey, true)
                );
                break;
            case Jwt::ALG_METHOD_HS256:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    hash_hmac('sha256', $content, $this->secretKey, true)
                );
                break;
            case Jwt::ALG_METHOD_AES:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    openssl_encrypt($content, 'AES-128-ECB', $this->secretKey)
                );
                break;
            default:
                throw new UnexpectedValueException('Alg is invalid！');
        }

        return $signature;
    }

}
