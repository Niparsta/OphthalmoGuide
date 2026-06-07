SELECT 'CREATE DATABASE authentik'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'authentik')\gexec

SELECT 'CREATE DATABASE ophthalmoguide'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ophthalmoguide')\gexec
