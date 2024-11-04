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

switch ($method) {
    case 'GET':
        try {
            // Get all categories for the user
            $stmt = $db->prepare(
                "SELECT id, category_name 
                 FROM categories 
                 WHERE user_id = ? 
                 ORDER BY category_name ASC"
            );
            $stmt->execute([$userId]);
            
            $categories = $stmt->fetchAll();
            
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "data" => $categories
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
        
        if (!empty($data->category_name)) {
            try {
                // Check if category name already exists for this user
                $check_stmt = $db->prepare(
                    "SELECT id 
                     FROM categories 
                     WHERE user_id = ? AND category_name = ?"
                );
                $check_stmt->execute([$userId, $data->category_name]);
                
                if ($check_stmt->rowCount() > 0) {
                    http_response_code(400);
                    echo json_encode([
                        "success" => false,
                        "message" => "Category name already exists."
                    ]);
                    exit;
                }

                // Create new category
                $stmt = $db->prepare(
                    "INSERT INTO categories (user_id, category_name) 
                     VALUES (?, ?)"
                );
                
                if ($stmt->execute([$userId, $data->category_name])) {
                    $categoryId = $db->lastInsertId();
                    
                    http_response_code(201);
                    echo json_encode([
                        "success" => true,
                        "message" => "Category created successfully.",
                        "data" => [
                            "id" => $categoryId,
                            "category_name" => $data->category_name
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
                "message" => "Unable to create category. Category name is required."
            ]);
        }
        break;

    case 'PUT':
        $data = json_decode(file_get_contents("php://input"));
        
        if (!empty($data->id) && !empty($data->category_name)) {
            try {
                // Check if category exists and belongs to user
                $check_stmt = $db->prepare(
                    "SELECT id 
                     FROM categories 
                     WHERE id = ? AND user_id = ?"
                );
                $check_stmt->execute([$data->id, $userId]);
                
                if ($check_stmt->rowCount() === 0) {
                    http_response_code(404);
                    echo json_encode([
                        "success" => false,
                        "message" => "Category not found or access denied."
                    ]);
                    exit;
                }

                // Check if new name already exists for other categories
                $name_check = $db->prepare(
                    "SELECT id 
                     FROM categories 
                     WHERE user_id = ? AND category_name = ? AND id != ?"
                );
                $name_check->execute([$userId, $data->category_name, $data->id]);
                
                if ($name_check->rowCount() > 0) {
                    http_response_code(400);
                    echo json_encode([
                        "success" => false,
                        "message" => "Category name already exists."
                    ]);
                    exit;
                }

                // Update category
                $stmt = $db->prepare(
                    "UPDATE categories 
                     SET category_name = ? 
                     WHERE id = ? AND user_id = ?"
                );
                
                if ($stmt->execute([$data->category_name, $data->id, $userId])) {
                    http_response_code(200);
                    echo json_encode([
                        "success" => true,
                        "message" => "Category updated successfully.",
                        "data" => [
                            "id" => $data->id,
                            "category_name" => $data->category_name
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
                "message" => "Unable to update category. ID and category name are required."
            ]);
        }
        break;

    case 'DELETE':
        $categoryId = isset($_GET['id']) ? $_GET['id'] : null;
        
        if ($categoryId) {
            try {
                // Check if category exists and belongs to user
                $check_stmt = $db->prepare(
                    "SELECT id 
                     FROM categories 
                     WHERE id = ? AND user_id = ?"
                );
                $check_stmt->execute([$categoryId, $userId]);
                
                if ($check_stmt->rowCount() === 0) {
                    http_response_code(404);
                    echo json_encode([
                        "success" => false,
                        "message" => "Category not found or access denied."
                    ]);
                    exit;
                }

                // Delete category
                $stmt = $db->prepare(
                    "DELETE FROM categories 
                     WHERE id = ? AND user_id = ?"
                );
                
                if ($stmt->execute([$categoryId, $userId])) {
                    http_response_code(200);
                    echo json_encode([
                        "success" => true,
                        "message" => "Category deleted successfully."
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
                "message" => "Unable to delete category. Category ID is required."
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