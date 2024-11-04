<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../src/FirebaseJWT.php';

$database = new Database();
$db = $database->getConnection();
$jwt = new FirebaseJWT();

// Handle request method
$method = $_SERVER['REQUEST_METHOD'];
$endpoint = isset($_GET['action']) ? $_GET['action'] : '';

function addDefaultCategories($userId, $db) {
    $defaultCategories = [
        "Social Media",
        "Entertainment",
        "Communication",
        "Education"
    ];

    foreach ($defaultCategories as $categoryName) {
        $stmt = $db->prepare("INSERT INTO categories (user_id, category_name) VALUES (?, ?)");
        $stmt->execute([$userId, $categoryName]);
    }
}


if ($method === 'POST') {
    // Get posted data
    $data = json_decode(file_get_contents("php://input"));

    switch ($endpoint) {
        case 'register':
            if (
                !empty($data->full_name) &&
                !empty($data->username) &&
                !empty($data->pin)
            ) {
                try {
                    // Check if username already exists
                    $check_stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
                    $check_stmt->execute([$data->username]);
                    
                    if ($check_stmt->rowCount() > 0) {
                        http_response_code(400);
                        echo json_encode([
                            "success" => false,
                            "message" => "Username already exists."
                        ]);
                        exit;
                    }

                    // Hash the PIN
                    $hashed_pin = password_hash($data->pin, PASSWORD_DEFAULT);

                    // Prepare insert statement
                    $stmt = $db->prepare(
                        "INSERT INTO users (full_name, username, pin) 
                         VALUES (?, ?, ?)"
                    );

                    // Execute insert
                    if ($stmt->execute([
                        $data->full_name,
                        $data->username,
                        $hashed_pin
                    ])) {
                        $userId = $db->lastInsertId();
                                        // Tambahkan kategori default setelah pengguna terdaftar
                addDefaultCategories($userId, $db);
                        
                        // Generate token
                        $token = $jwt->generateToken($userId, $data->username);

                        http_response_code(201);
                        echo json_encode([
                            "success" => true,
                            "message" => "User registered successfully.",
                            "token" => $token,
                            "user" => [
                                "id" => $userId,
                                "full_name" => $data->full_name,
                                "username" => $data->username
                            ]
                        ]);
                    }
                } catch (PDOException $e) {
                    http_response_code(500);
                    echo json_encode([
                        "success" => false,
                        "message" => "Database error: " . $e->getMessage()
                    ]);
                }
            } else {
                http_response_code(400);
                echo json_encode([
                    "success" => false,
                    "message" => "Unable to register. Data is incomplete."
                ]);
            }
            break;

        case 'login':
            if (!empty($data->username) && !empty($data->pin)) {
                try {
                    // Get user data
                    $stmt = $db->prepare(
                        "SELECT id, full_name, username, pin 
                         FROM users 
                         WHERE username = ?"
                    );
                    $stmt->execute([$data->username]);

                    if ($stmt->rowCount() > 0) {
                        $user = $stmt->fetch();

                        // Verify PIN
                        if (password_verify($data->pin, $user['pin'])) {
                            // Generate token
                            $token = $jwt->generateToken($user['id'], $user['username']);

                            http_response_code(200);
                            echo json_encode([
                                "success" => true,
                                "message" => "Login successful.",
                                "token" => $token,
                                "user" => [
                                    "id" => $user['id'],
                                    "full_name" => $user['full_name'],
                                    "username" => $user['username']
                                ]
                            ]);
                        } else {
                            http_response_code(401);
                            echo json_encode([
                                "success" => false,
                                "message" => "Invalid PIN."
                            ]);
                        }
                    } else {
                        http_response_code(401);
                        echo json_encode([
                            "success" => false,
                            "message" => "User not found."
                        ]);
                    }
                } catch (PDOException $e) {
                    http_response_code(500);
                    echo json_encode([
                        "success" => false,
                        "message" => "Database error: " . $e->getMessage()
                    ]);
                }
            } else {
                http_response_code(400);
                echo json_encode([
                    "success" => false,
                    "message" => "Unable to login. Data is incomplete."
                ]);
            }
            break;

        default:
            http_response_code(404);
            echo json_encode([
                "success" => false,
                "message" => "Unknown endpoint."
            ]);
            break;
    }
} else {
    http_response_code(405);
    echo json_encode([
        "success" => false,
        "message" => "Method not allowed."
    ]);
}