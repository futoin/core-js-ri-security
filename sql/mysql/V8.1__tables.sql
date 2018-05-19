
CREATE TABLE sec_users (
    `_id` INT UNSIGNED NOT NULL auto_increment PRIMARY KEY,
    `local_id` CHARACTER(22) NOT NULL UNIQUE,
    `global_id` VARCHAR(128) NOT NULL UNIQUE,
    `is_local` ENUM('N', 'Y') NOT NULL,
    `is_service` ENUM('N', 'Y') NOT NULL,
    `is_enabled` ENUM('N', 'Y') NOT NULL,
    `ms_max` SMALLINT,
    `ds_max` SMALLINT,
    `created` DATETIME NOT NULL,
    `updated` DATETIME NOT NULL
) ENGINE=InnoDB;
