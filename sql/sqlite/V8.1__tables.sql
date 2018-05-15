
CREATE TABLE sec_users (
    `uuidb64` CHARACTER(22) NOT NULL UNIQUE,
    `global_id` VARCHAR(128) NOT NULL UNIQUE,
    `is_local` CHARACTER(1) NOT NULL,
    `is_enabled` CHARACTER(1) NOT NULL,
    `created` TIMESTAMP NOT NULL
);
