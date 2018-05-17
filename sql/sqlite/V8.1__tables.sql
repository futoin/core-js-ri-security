
CREATE TABLE sec_users (
    "local_id" CHARACTER(22) NOT NULL PRIMARY KEY,
    "global_id" VARCHAR(128) NOT NULL UNIQUE,
    "is_local" CHARACTER(1) NOT NULL,
    "is_service" CHARACTER(1) NOT NULL,
    "is_enabled" CHARACTER(1) NOT NULL,
    "created" TIMESTAMP NOT NULL,
    "updated" TIMESTAMP NOT NULL
);
