
CREATE SCHEMA ftnsec;
CREATE TYPE ftnsec.enabled_enum AS ENUM('N', 'Y');

CREATE TABLE sec_users (
    "uuidb64" CHARACTER(22) NOT NULL UNIQUE,
    "global_id" VARCHAR(128) NOT NULL UNIQUE,
    "is_local" ftnsec.enabled_enum NOT NULL,
    "is_enabled" ftnsec.enabled_enum NOT NULL,
    "created" TIMESTAMP NOT NULL
);
