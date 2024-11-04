<?php
require_once __DIR__ . '/../config/database.php';

$database = new Database();
$db = $database->getConnection();

// Daftar kategori default
$defaultCategories = [
    "Social Media",
    "Entertainment",
    "Communication",
    "Education"
];

// Tambahkan kategori default untuk pengguna baru
function addDefaultCategories($userId, $db, $defaultCategories) {
    foreach ($defaultCategories as $categoryName) {
        $stmt = $db->prepare("INSERT INTO categories (user_id, category_name) VALUES (?, ?)");
        $stmt->execute([$userId, $categoryName]);
    }
}

?>
