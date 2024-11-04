<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../src/FirebaseJWT.php';

$database = new Database();
$db = $database->getConnection();
$jwt = new FirebaseJWT();

// Validate token for all requests
$auth = $jwt->validateAuthHeader();
if (!$auth['success']) {
    http_response_code(401);
    echo json_encode([
        "success" => false,
        "message" => "Unauthorized access."
    ]);
    exit;
}

$userId = $auth['data']->userId;
$method = $_SERVER['REQUEST_METHOD'];

// Function to get Clearbit logo URL
function getClearbitLogoUrl($domain) {
    return "https://logo.clearbit.com/" . $domain;
}

// Function to extract domain from platform name
function extractDomain($platform) {
    // Remove spaces and special characters
    $domain = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $platform));
    return $domain . ".com";
}

switch ($method) {
    case 'GET':
        try {
            $categoryId = isset($_GET['category_id']) ? $_GET['category_id'] : null;
            
            $query = "SELECT p.*, c.category_name 
                     FROM passwords p 
                     LEFT JOIN categories c ON p.category_id = c.id 
                     WHERE p.user_id = ?";
            $params = [$userId];
            
            if ($categoryId) {
                $query .= " AND p.category_id = ?";
                $params[] = $categoryId;
            }
            
            $query .= " ORDER BY p.platform ASC";
            
            $stmt = $db->prepare($query);
            $stmt->execute($params);
            
            $passwords = $stmt->fetchAll();
            
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "data" => $passwords
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode([
                "success" => false,
                "message" => "Database error: " . $e->getMessage()
            ]);
        }
        break;

    case 'POST':
        $data = json_decode(file_get_contents("php://input"));
        
        if (!empty($data->platform) && !empty($data->email) && !empty($data->password)) {
            try {
                // Get logo URL from Clearbit
                $domain = extractDomain($data->platform);
                $logoUrl = getClearbitLogoUrl($domain);
                
                // Validate category if provided
                if (!empty($data->category_id)) {
                    $cat_check = $db->prepare("SELECT id FROM categories WHERE id = ? AND user_id = ?");
                    $cat_check->execute([$data->category_id, $userId]);
                    
                    if ($cat_check->rowCount() === 0) {
                        http_response_code(400);
                        echo json_encode([
                            "success" => false,
                            "message" => "Invalid category ID."
                        ]);
                        exit;
                    }
                }

                $stmt = $db->prepare(
                    "INSERT INTO passwords (user_id, platform, img_platform, email, password, category_id) 
                     VALUES (?, ?, ?, ?, ?, ?)"
                );
                
                if ($stmt->execute([
                    $userId,
                    $data->platform,
                    $logoUrl,
                    $data->email,
                    $data->password,
                    $data->category_id ?? null
                ])) {
                    $passwordId = $db->lastInsertId();
                    
                    http_response_code(201);
                    echo json_encode([
                        "success" => true,
                        "message" => "Password entry created successfully.",
                        "data" => [
                            "id" => $passwordId,
                            "platform" => $data->platform,
                            "img_platform" => $logoUrl,
                            "email" => $data->email,
                            "category_id" => $data->category_id ?? null
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
                "message" => "Unable to create password entry. Required fields are missing."
            ]);
        }
        break;

    case 'PUT':
        $data = json_decode(file_get_contents("php://input"));
        
        if (!empty($data->id) && (!empty($data->platform) || !empty($data->email) || !empty($data->password) || isset($data->category_id))) {
            try {
                // Check if password entry exists and belongs to user
                $check_stmt = $db->prepare("SELECT * FROM passwords WHERE id = ? AND user_id = ?");
                $check_stmt->execute([$data->id, $userId]);
                
                if ($check_stmt->rowCount() === 0) {
                    http_response_code(404);
                    echo json_encode([
                        "success" => false,
                        "message" => "Password entry not found or access denied."
                    ]);
                    exit;
                }

                $current_data = $check_stmt->fetch();
                
                // Validate category if provided
                if (isset($data->category_id) && $data->category_id !== null) {
                    $cat_check = $db->prepare("SELECT id FROM categories WHERE id = ? AND user_id = ?");
                    $cat_check->execute([$data->category_id, $userId]);
                    
                    if ($cat_check->rowCount() === 0) {
                        http_response_code(400);
                        echo json_encode([
                            "success" => false,
                            "message" => "Invalid category ID."
                        ]);
                        exit;
                    }
                }

                // Update logo URL if platform is changed
                $logoUrl = $current_data['img_platform'];
                if (!empty($data->platform) && $data->platform !== $current_data['platform']) {
                    $domain = extractDomain($data->platform);
                    $logoUrl = getClearbitLogoUrl($domain);
                }

                $query = "UPDATE passwords SET ";
                $params = [];
                $updates = [];

                if (!empty($data->platform)) {
                    $updates[] = "platform = ?";
                    $params[] = $data->platform;
                    $updates[] = "img_platform = ?";
                    $params[] = $logoUrl;
                }
                if (!empty($data->email)) {
                    $updates[] = "email = ?";
                    $params[] = $data->email;
                }
                if (!empty($data->password)) {
                    $updates[] = "password = ?";
                    $params[] = $data->password;
                }
                if (isset($data->category_id)) {
                    $updates[] = "category_id = ?";
                    $params[] = $data->category_id;
                }

                $query .= implode(", ", $updates);
                $query .= " WHERE id = ? AND user_id = ?";
                $params[] = $data->id;
                $params[] = $userId;

                $stmt = $db->prepare($query);
                
                if ($stmt->execute($params)) {
                    http_response_code(200);
                    echo json_encode([
                        "success" => true,
                        "message" => "Password entry updated successfully."
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
                "message" => "Unable to update password entry. Required fields are missing."
            ]);
        }
        break;

    case 'DELETE':
        $passwordId = isset($_GET['id']) ? $_GET['id'] : null;
        
        if ($passwordId) {
            try {
                // Check if password entry exists and belongs to user
                $check_stmt = $db->prepare("SELECT id FROM passwords WHERE id = ? AND user_id = ?");
                $check_stmt->execute([$passwordId, $userId]);
                
                if ($check_stmt->rowCount() === 0) {
                    http_response_code(404);
                    echo json_encode([
                        "success" => false,
                        "message" => "Password entry not found or access denied."
                    ]);
                    exit;
                }

                $stmt = $db->prepare("DELETE FROM passwords WHERE id = ? AND user_id = ?");
                
                if ($stmt->execute([$passwordId, $userId])) {
                    http_response_code(200);
                    echo json_encode([
                        "success" => true,
                        "message" => "Password entry deleted successfully."
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
                "message" => "Unable to delete password entry. Password ID is required."
            ]);
        }
        break;

    default:
        http_response_code(405);
        echo json_encode([
            "success" => false,
            "message" => "Method not allowed"
        ]);
        break;
}