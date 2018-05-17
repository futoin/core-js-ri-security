
CREATE SCHEMA ftnsec;
CREATE TYPE ftnsec.enabled_enum AS ENUM('N', 'Y');
CREATE DOMAIN ftnsec.uuid_b64 AS CHARACTER(22);

CREATE TABLE sec_users (
    "local_id" ftnsec.uuid_b64 NOT NULL PRIMARY KEY,
    "global_id" VARCHAR(128) NOT NULL UNIQUE,
    "is_local" ftnsec.enabled_enum NOT NULL,
    "is_service" ftnsec.enabled_enum NOT NULL,
    "is_enabled" ftnsec.enabled_enum NOT NULL,
    "created" TIMESTAMP NOT NULL,
    "updated" TIMESTAMP NOT NULL
);
