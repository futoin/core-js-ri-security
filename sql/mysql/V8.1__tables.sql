
CREATE TABLE sec_users (
    `_id` INT UNSIGNED NOT NULL auto_increment PRIMARY KEY,
    `uuidb64` CHARACTER(22) NOT NULL UNIQUE,
    `global_id` VARCHAR(128) NOT NULL UNIQUE,
    `is_local` ENUM('N', 'Y') NOT NULL,
    `is_enabled` ENUM('N', 'Y') NOT NULL,
    `created` DATETIME NOT NULL
) ENGINE=InnoDB;
