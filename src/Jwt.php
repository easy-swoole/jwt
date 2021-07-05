<?php


namespace EasySwoole\Jwt;


class Jwt
{
    private static $instance;

    private $secretKey = 'EasySwoole';
    protected $prefix;

    private $alg = Jwt::ALG_METHOD_HS256; // 默认加密方式

    public const ALG_METHOD_AES = 'AES';
    public const ALG_METHOD_HMACSHA256 = 'HMACSHA256';
    public const ALG_METHOD_HS256 = 'HS256';
    public const ALG_METHOD_RS256 = 'RS256';

    public static function getInstance(): Jwt
    {
        if (!isset(self::$instance)) {
            self::$instance = new Jwt();
        }
        return self::$instance;
    }

    public function setSecretKey(string $key): Jwt
    {
        $this->secretKey = $key;
        return $this;
    }

    public function setAlg(string $alg): Jwt
    {
        $this->alg = $alg;
        return $this;
    }

    public function publish(): JwtObject
    {
        return new JwtObject(['secretKey' => $this->secretKey]);
    }

    /**
     * @throws Exception
     */
    public function decode(string $raw): ?JwtObject
    {
        if (strpos($raw, ' ')) {
            $prefix       = explode(' ', $raw);
            $this->prefix = $prefix[0];
            $raw          = str_replace($this->prefix . ' ', '', $raw);
        }

        $items = explode('.', $raw);

        // token格式
        if (count($items) !== 3) {
            throw new Exception('Token format error!');
        }

        // 验证header
        $header = Encryption::getInstance()->base64UrlDecode($items[0]);
        $header = json_decode($header, true);
        if (empty($header)) {
            throw new Exception('Token header is empty!');
        }

        // 验证payload
        $payload = Encryption::getInstance()->base64UrlDecode($items[1]);
        $payload = json_decode($payload, true);
        if (empty($payload)) {
            throw new Exception('Token payload is empty!');
        }

        if (empty($items[2])) {
            throw new Exception('Signature is empty!');
        }

        $jwtObjConfig = array_merge(
            $header,
            $payload,
            [
                'header' => $items[0],
                'payload' => $items[1],
                'signature' => $items[2],
                'secretKey' => $this->secretKey,
                'alg' => $this->alg
            ],
            ['prefix' => $this->prefix]
        );
        return new JwtObject($jwtObjConfig, true);
    }

}
