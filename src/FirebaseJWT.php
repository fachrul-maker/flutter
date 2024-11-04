

<?php

require_once __DIR__ . '/../vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class FirebaseJWT {
    private $key = "06eae0856bcc3ebce5fae170576332908b755103c7c907fbc7cc45943710732a363d0b66b6d691a801cb2933d4e2db53fa0a8cd850512dd489f4fcd05f9e3828fba0bc8da543a61a417bd5d0249c4e35b93f573d7e293e012c2e8b3bef78981b28336d57ffecb14d420d6d512b61f6a8cfa7a934a22faffb69ed1c8caac3a68abfc7ee023de76f37d0e018941306e117c4dd45283bfd557bb7b094a723a5e2aa4f1a90ac0f00612633e022cc9de0b181e1ae0431ca1ec5c9295cb09f2c2a0c91b0aefa7d394bb54c59bda1756ed367e1eb95c113a97228354a067fcf0fe5f5a0463c6745fb3b4832d1fae002d1c4dd458abc43d00f4dc4e346f1cdec32f1130f"; // Ganti dengan secret key yang lebih aman
    private $algorithm = 'HS256';
    private $issuer = 'passhub';
    private $audience = 'passhub_app';

    // Generate token
    public function generateToken($userId, $username) {
        $issuedAt = time();
        $expirationTime = $issuedAt + 60 * 60 * 24; // Token berlaku 24 jam

        $payload = [
            'iss' => $this->issuer,      // issuer
            'aud' => $this->audience,     // audience
            'iat' => $issuedAt,           // issued at
            'exp' => $expirationTime,     // expiration
            'data' => [
                'userId' => $userId,
                'username' => $username
            ]
        ];

        return JWT::encode($payload, $this->key, $this->algorithm);
    }

    // Validasi token
    public function validateToken($token) {
        try {
            $decoded = JWT::decode($token, new Key($this->key, $this->algorithm));
            return [
                'success' => true,
                'data' => $decoded->data
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }

    // Get user ID from token
    public function getUserIdFromToken($token) {
        $result = $this->validateToken($token);
        if ($result['success']) {
            return $result['data']->userId;
        }
        return null;
    }

    // Middleware untuk validasi token dari header
    public function validateAuthHeader() {
        $headers = getallheaders();
        
        // Cek apakah ada header Authorization
        if (!isset($headers['Authorization'])) {
            http_response_code(401);
            return [
                'success' => false,
                'message' => 'No token provided'
            ];
        }

        // Ambil token dari header
        $authHeader = $headers['Authorization'];
        $token = str_replace('Bearer ', '', $authHeader);

        // Validasi token
        $result = $this->validateToken($token);
        if (!$result['success']) {
            http_response_code(401);
            return [
                'success' => false,
                'message' => 'Invalid token'
            ];
        }

        return $result;
    }
}