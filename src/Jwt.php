<?php

declare(strict_types=1);

namespace Atoms\Jwt;

use ArrayAccess;
use DateTime;
use InvalidArgumentException;
use RuntimeException;

class Jwt
{
    /**
     * @var array A list of supported algorithms
     */
    private const SUPPORTED_ALGORITHMS = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512'],
    ];

    /**
     * Converts and signs an array into a JWT string.
     *
     * @param array $payload
     * @param string|resource $key
     * @param string $algorithm
     * @param mixed $keyId
     * @param array $headers
     * @return string
     */
    public function encode(
        array $payload,
        $key,
        string $algorithm = 'HS256',
        $keyId = null,
        array $headers = []
    ): string {
        $headers = array_merge($headers, [
            'typ' => 'JWT',
            'alg' => $algorithm
        ]);

        if (!is_null($keyId)) {
            $headers['kid'] = $keyId;
        }

        $segments = [
            $this->base64UrlEncode($this->jsonEncode($headers)),
            $this->base64UrlEncode($this->jsonEncode($payload))
        ];

        $signature = $this->sign(implode('.', $segments), $key, $algorithm);

        $segments[] = $this->base64UrlEncode($signature);

        return implode('.', $segments);
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string $jwt
     * @param string|array $key
     * @param array $allowedAlgorithms
     * @param int|null $timestamp
     * @param int $leeway
     * @return mixed
     * @throws \ExpirationTimeException
     * @throws \InvalidArgumentException
     * @throws \InvalidSignatureException
     * @throws \IssuedAtException
     * @throws \NotBeforeException
     *
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     * @SuppressWarnings(PHPMD.NPathComplexity)
     */
    public function decode(
        string $jwt,
        $key,
        array $allowedAlgorithms = [],
        ?int $timestamp = null,
        int $leeway = 0
    ) {
        if (empty($key)) {
            throw new InvalidArgumentException('Invalid key; must not be empty');
        }

        if (is_null($timestamp)) {
            $timestamp = time();
        }

        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidArgumentException('Invalid JWT; wrong number of segments');
        }

        list($encodedHeader, $encodedPayload, $encodedSignature) = $segments;

        $header = $this->jsonDecode($this->base64UrlDecode($encodedHeader));
        $payload = $this->jsonDecode($this->base64UrlDecode($encodedPayload));
        $signature = $this->base64UrlDecode($encodedSignature);

        if (is_null($header)) {
            throw new InvalidArgumentException('Invalid header encoding');
        }

        if (is_null($payload)) {
            throw new InvalidArgumentException('Invalid payload encoding');
        }

        if ($signature === false) {
            throw new InvalidArgumentException('Invalid signature encoding');
        }

        /** Check for a valid algorithm */
        if (!isset($header->alg) || !isset(self::SUPPORTED_ALGORITHMS[$header->alg])) {
            throw new InvalidArgumentException('Invalid algorithm; empty or not supported');
        }

        if (!in_array($header->alg, $allowedAlgorithms)) {
            throw new InvalidArgumentException('Invalid algorithm; not allowed');
        }

        /** If multiple keys are used; find the correct one */
        if (is_array($key) || $key instanceof ArrayAccess) {
            if (!isset($header->kid)) {
                throw new InvalidArgumentException('Invalid Key ID (kid); missing claim');
            }

            if (!isset($key[$header->kid])) {
                throw new InvalidArgumentException('Invalid Key ID (kid); not defined');
            }

            $key = $key[$header->kid];
        }

        /** Verify the signature */
        if (!$this->verify("{$encodedHeader}.{$encodedPayload}", $signature, $key, $header->alg)) {
            throw new InvalidSignatureException('Invalid signature; verification failed');
        }

        /** If the "nbf" (Not Before) claim is defined; check if the timestamp has passed */
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + $leeway)) {
            $date = new DateTime();
            $date->setTimestamp($payload->nbf);

            throw new NotBeforeException('Cannot handle token prior to ' . $date->format('c'));
        }

        /** If the "iat" (Issued At) claim is defined; check if the timestamp has passed */
        if (isset($payload->iat) && $payload->iat > ($timestamp + $leeway)) {
            $date = new DateTime();
            $date->setTimestamp($payload->iat);

            throw new IssuedAtException('Cannot handle token prior to ' . $date->format('c'));
        }

        /** If the "exp" (Expiration Time) claim is defined; check if the token has expired */
        if (isset($payload->exp) && $payload->exp < ($timestamp - $leeway)) {
            throw new ExpirationTimeException('Expired token');
        }

        return $payload;
    }

    /**
     * Signs a string with a given key and algorithm.
     *
     * @param string $message
     * @param string|resource $key
     * @param string $algorithm
     * @return string
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public function sign(string $message, $key, string $algorithm): string
    {
        if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            throw new InvalidArgumentException('Invalid algorithm; not supported');
        }

        list($function, $algorithmName) = self::SUPPORTED_ALGORITHMS[$algorithm];

        if ($function === 'hash_hmac') {
            return hash_hmac($algorithmName, $message, $key, true);
        } elseif ($function === 'openssl') {
            $signature = '';

            if (openssl_sign($message, $signature, $key, $algorithmName) === false) {
                throw new RuntimeException('OpenSSL unable to sign message');
            }

            return $signature;
        }

        throw new InvalidArgumentException('Invalid algorithm; not supported');
    }

    /**
     * Verifies a signature with the message, key and method.
     *
     * @param string $message
     * @param string $signature
     * @param string|resource $key
     * @param string $algorithm
     * @return bool
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private function verify(string $message, string $signature, $key, string $algorithm): bool
    {
        if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            throw new InvalidArgumentException('Invalid algorithm; not supported');
        }

        list($function, $algorithmName) = self::SUPPORTED_ALGORITHMS[$algorithm];

        if ($function === 'openssl') {
            $success = openssl_verify($message, $signature, $key, $algorithmName);

            if ($success === -1) {
                throw new RuntimeException('OpenSSL error: ' . openssl_error_string());
            }

            return (bool)$success;
        }

        $hash = hash_hmac($algorithmName, $message, $key, true);

        return hash_equals($signature, $hash);
    }

    /**
     * Encodes a object/array into a JSON string.
     *
     * @param object|array $input
     * @return string
     * @throws \RuntimeException
     */
    private function jsonEncode($input): string
    {
        $json = json_encode($input);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Unable to encode object/array into JSON: ' . json_last_error());
        }

        /** @todo Should we check for 'null' JSON? */

        return $json;
    }

    /**
     * Decodes a JSON string into a PHP object.
     *
     * @param string $input
     * @return mixed
     * @throws \RuntimeException
     */
    private function jsonDecode(string $input)
    {
        $object = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Unable to decode JSON into object: ' . json_last_error());
        }

        return $object;
    }

    /**
     * Encodes a string with URL safe Base64.
     *
     * @param string $input
     * @return string
     */
    private function base64UrlEncode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Decodes a string with URL safe Base64.
     *
     * @param string $input
     * @return string
     */
    private function base64UrlDecode(string $input): string
    {
        $remainder = strlen($input) % 4;

        if ($remainder > 0) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }
}
