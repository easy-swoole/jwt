<?php
/**
 * @CreateTime:   2020/11/18 10:16 下午
 * @Author:       huizhang  <2788828128@qq.com>
 * @Copyright:    copyright(2020) Easyswoole all rights reserved
 * @Description:  签名生成
 */

namespace EasySwoole\Jwt;

use EasySwoole\Spl\SplBean;

class Signature extends SplBean
{

    protected $secretKey;
    protected $header;
    protected $payload;
    protected $alg;

    /**
     * php 7.4以下不支持在__toString()抛出异常
     */
    public function __toString()
    {
        $content = $this->header . '.' . $this->payload;

        $signature = "";
        switch ($this->alg) {
            case Jwt::ALG_METHOD_HMACSHA256:
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
            case Jwt::ALG_METHOD_RS256:
                $success = openssl_sign($content, $signature, $this->secretKey, 'SHA256');
                if (!$success) {
                    $signature = "";
                } else {
                    $signature = Encryption::getInstance()->base64UrlEncode($signature);
                }
                break;
            default:
                $signature = "";
        }
        return $signature;
    }

}
