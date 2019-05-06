CREATE DATABASE IF NOT EXISTS idp_dev;
GRANT ALL PRIVILEGES ON idp_dev.* TO 'idp'@'%';


-- create table, function and trigger
CREATE TABLE if not exists last_update ( id serial, tstamp timestamp DEFAULT now());
INSERT INTO last_update VALUES(1, now());
CREATE OR REPLACE FUNCTION log_last_changes() RETURNS trigger AS $BODY$ BEGIN UPDATE last_update SET tstamp = now() WHERE id = 1; RETURN NEW; END; $BODY$ language plpgsql;
DROP TRIGGER IF EXISTS last_change ON casbin_rules;
CREATE TRIGGER last_change AFTER INSERT OR UPDATE OR DELETE ON casbin_rules FOR EACH STATEMENT EXECUTE PROCEDURE log_last_changes();

-- create user and casbin rule
INSERT INTO ab_users VALUES(999,now(),now(),null,'admin','admin@hiveon.net','$2a$10$lmWdGp8ZJsFz5wJ9X8fi7uZ95XTC6zcx/trmd/TBuR3znx6.egrVC',null,null,true);
INSERT INTO casbin_rules VALUES(999, now(), now(), null, 'p', '999', '/*', '*');