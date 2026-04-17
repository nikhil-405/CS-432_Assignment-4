# Data Splitting and Verification Queries

This document captures the SQL used to split existing tenant data across 3 simulated shards using shard key OrganizationID with rule:

- shard index = OrganizationID % 3
- shard 0 tables use prefix shard0_
- shard 1 tables use prefix shard1_
- shard 2 tables use prefix shard2_

Core tables are not sharded and stay on shard 0:
CoreUsers, CoreSessions, CoreMemberLinks, CoreGroupMemberships, CoreAuditLogs, CoreAuditState, organizations, roles, policies, tags.

## 1) Split queries (run on source database)

Users (direct by OrganizationID):

    INSERT INTO shard0_users SELECT * FROM users WHERE MOD(OrganizationID, 3) = 0;
    INSERT INTO shard1_users SELECT * FROM users WHERE MOD(OrganizationID, 3) = 1;
    INSERT INTO shard2_users SELECT * FROM users WHERE MOD(OrganizationID, 3) = 2;

Documents (direct by OrganizationID):

    INSERT INTO shard0_documents SELECT * FROM documents WHERE MOD(OrganizationID, 3) = 0;
    INSERT INTO shard1_documents SELECT * FROM documents WHERE MOD(OrganizationID, 3) = 1;
    INSERT INTO shard2_documents SELECT * FROM documents WHERE MOD(OrganizationID, 3) = 2;

Permissions (by document organization):

    INSERT INTO shard0_permissions
    SELECT p.*
    FROM permissions p
    JOIN documents d ON d.DocID = p.DocID
    WHERE MOD(d.OrganizationID, 3) = 0;

    INSERT INTO shard1_permissions
    SELECT p.*
    FROM permissions p
    JOIN documents d ON d.DocID = p.DocID
    WHERE MOD(d.OrganizationID, 3) = 1;

    INSERT INTO shard2_permissions
    SELECT p.*
    FROM permissions p
    JOIN documents d ON d.DocID = p.DocID
    WHERE MOD(d.OrganizationID, 3) = 2;

Logs (by document organization):

    INSERT INTO shard0_logs
    SELECT l.*
    FROM logs l
    JOIN documents d ON d.DocID = l.DocID
    WHERE MOD(d.OrganizationID, 3) = 0;

    INSERT INTO shard1_logs
    SELECT l.*
    FROM logs l
    JOIN documents d ON d.DocID = l.DocID
    WHERE MOD(d.OrganizationID, 3) = 1;

    INSERT INTO shard2_logs
    SELECT l.*
    FROM logs l
    JOIN documents d ON d.DocID = l.DocID
    WHERE MOD(d.OrganizationID, 3) = 2;

Versions (by document organization):

    INSERT INTO shard0_versions
    SELECT v.*
    FROM versions v
    JOIN documents d ON d.DocID = v.DocID
    WHERE MOD(d.OrganizationID, 3) = 0;

    INSERT INTO shard1_versions
    SELECT v.*
    FROM versions v
    JOIN documents d ON d.DocID = v.DocID
    WHERE MOD(d.OrganizationID, 3) = 1;

    INSERT INTO shard2_versions
    SELECT v.*
    FROM versions v
    JOIN documents d ON d.DocID = v.DocID
    WHERE MOD(d.OrganizationID, 3) = 2;

Passwords (by document organization):

    INSERT INTO shard0_passwords
    SELECT pw.*
    FROM passwords pw
    JOIN documents d ON d.DocID = pw.DocID
    WHERE MOD(d.OrganizationID, 3) = 0;

    INSERT INTO shard1_passwords
    SELECT pw.*
    FROM passwords pw
    JOIN documents d ON d.DocID = pw.DocID
    WHERE MOD(d.OrganizationID, 3) = 1;

    INSERT INTO shard2_passwords
    SELECT pw.*
    FROM passwords pw
    JOIN documents d ON d.DocID = pw.DocID
    WHERE MOD(d.OrganizationID, 3) = 2;

UserPasswords (by user organization):

    INSERT INTO shard0_userpasswords
    SELECT up.*
    FROM userpasswords up
    JOIN users u ON u.UserID = up.UserID
    WHERE MOD(u.OrganizationID, 3) = 0;

    INSERT INTO shard1_userpasswords
    SELECT up.*
    FROM userpasswords up
    JOIN users u ON u.UserID = up.UserID
    WHERE MOD(u.OrganizationID, 3) = 1;

    INSERT INTO shard2_userpasswords
    SELECT up.*
    FROM userpasswords up
    JOIN users u ON u.UserID = up.UserID
    WHERE MOD(u.OrganizationID, 3) = 2;

DocPasswords (by document organization):

    INSERT INTO shard0_docpasswords
    SELECT dp.*
    FROM docpasswords dp
    JOIN documents d ON d.DocID = dp.DocID
    WHERE MOD(d.OrganizationID, 3) = 0;

    INSERT INTO shard1_docpasswords
    SELECT dp.*
    FROM docpasswords dp
    JOIN documents d ON d.DocID = dp.DocID
    WHERE MOD(d.OrganizationID, 3) = 1;

    INSERT INTO shard2_docpasswords
    SELECT dp.*
    FROM docpasswords dp
    JOIN documents d ON d.DocID = dp.DocID
    WHERE MOD(d.OrganizationID, 3) = 2;

Document tags (direct by OrgID):

    INSERT INTO shard0_document_tags SELECT * FROM document_tags WHERE MOD(OrgID, 3) = 0;
    INSERT INTO shard1_document_tags SELECT * FROM document_tags WHERE MOD(OrgID, 3) = 1;
    INSERT INTO shard2_document_tags SELECT * FROM document_tags WHERE MOD(OrgID, 3) = 2;
