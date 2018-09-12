<?php

declare(strict_types=1);

namespace Atoms\Jwt;

use ArrayObject;
use Atoms\Jwt\ExpirationTimeException;
use Atoms\Jwt\InvalidSignatureException;
use Atoms\Jwt\IssuedAtException;
use Atoms\Jwt\Jwt;
use Atoms\Jwt\NotBeforeException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class JwtTest extends TestCase
{
    public static $opensslVerifyReturnValue;

    public function testEncodeDecode()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->assertEquals(JWT::decode($msg, 'my_key', ['HS256']), ['abc']);
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9i' .
               'bGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(
            JWT::decode($msg, 'my_key', ['HS256']),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode(['f?'], 'a');
        $this->assertEquals(['f?'], JWT::decode($encoded, 'a', ['HS256']));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(RuntimeException::class);
        JWT::encode([pack('c', 128)], 'a');
    }

    // public function testMalformedJsonThrowsException()
    // {
    //     $this->expectException(RuntimeException::class);
    //     JWT::jsonDecode('this is not valid JSON string');
    // }

    public function testExpiredToken()
    {
        $this->expectException(ExpirationTimeException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20 // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', ['HS256']);
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(NotBeforeException::class);
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20 // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', ['HS256']);
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(IssuedAtException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 20 // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', ['HS256']);
    }

    public function testValidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20 // time in the future
            // 'exp' => time() + JWT::$leeway + 20); // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        // JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20 // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256'], null, 60);
        $this->assertEquals($decoded->message, 'abc');
        // JWT::$leeway = 0;
    }

    public function testExpiredTokenWithLeeway()
    {
        // JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 70 // time far in the past
        ];
        $this->expectException(ExpirationTimeException::class);
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256'], null, 60);
        $this->assertEquals($decoded->message, 'abc');
        // JWT::$leeway = 0;
    }

    public function testValidTokenWithList()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20 // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256', 'HS512']);
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbf()
    {
        $payload = [
            'message' => 'abc',
            'iat' => time(),
            'exp' => time() + 20, // time in the future
            'nbf' => time() - 20
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        // JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 20 // not before in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256'], null, 60);
        $this->assertEquals($decoded->message, 'abc');
        // JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        // JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 65 // not before too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(NotBeforeException::class);
        $decoded = JWT::decode($encoded, 'my_key', ['HS256'], null, 60);
        // JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway()
    {
        // JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 20 // issued in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256'], null, 60);
        $this->assertEquals($decoded->message, 'abc');
        // JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway()
    {
        // JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 65 // issued too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(IssuedAtException::class);
        $decoded = JWT::decode($encoded, 'my_key', ['HS256'], null, 60);
        // JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20 // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(InvalidSignatureException::class);
        $decoded = JWT::decode($encoded, 'my_key2', ['HS256']);
    }

    public function testNullKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() +  20 // time in the future
            // 'exp' => time() + JWT::$leeway + 20); // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(InvalidArgumentException::class);
        $decoded = JWT::decode($encoded, null, ['HS256']);
    }

    public function testEmptyKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20 // time in the future
            // 'exp' => time() + JWT::$leeway + 20); // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(InvalidArgumentException::class);
        $decoded = JWT::decode($encoded, '', ['HS256']);
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);
        $msg = JWT::encode(['abc'], $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, $pubKey, ['RS256']);
        $this->assertEquals($decoded, ['abc']);
    }

    public function testKIDChooser()
    {
        $keys = ['1' => 'my_key', '2' => 'my_key2'];
        $msg = JWT::encode(['abc'], $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, ['HS256']);
        $this->assertEquals($decoded, ['abc']);
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject(['1' => 'my_key', '2' => 'my_key2']);
        $msg = JWT::encode(['abc'], $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, ['HS256']);
        $this->assertEquals($decoded, ['abc']);
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($msg, 'my_key', ['none']);
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($msg, 'my_key', ['RS256']);
    }

    public function testMissingAlgorithm()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($msg, 'my_key');
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode(['abc'], 'my_key', 'HS256', null, ['cty' => 'test-eit;v=1']);
        $this->assertEquals(JWT::decode($msg, 'my_key', ['HS256']), ['abc']);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException(InvalidArgumentException::class);
        JWT::decode('brokenheader.brokenbody', 'my_key', ['HS256']);
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.' .
               'Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx';
        $this->expectException(InvalidSignatureException::class);
        JWT::decode($msg, 'secret', ['HS256']);
    }

    public function testVerifyError()
    {
        $this->expectException(RuntimeException::class);
        $pkey = openssl_pkey_new(['private_key_bits' => 1024]);
        $msg = JWT::encode(['abc'], $pkey, 'RS256');
        self::$opensslVerifyReturnValue = -1;
        JWT::decode($msg, $pkey, ['RS256']);
    }
}

/*
 * Allows the testing of openssl_verify with an error return value
 */
function openssl_verify($msg, $signature, $key, $algorithm)
{
    if (!is_null(JwtTest::$opensslVerifyReturnValue)) {
        return JwtTest::$opensslVerifyReturnValue;
    }

    return \openssl_verify($msg, $signature, $key, $algorithm);
}
