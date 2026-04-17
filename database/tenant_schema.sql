-- MySQL dump 10.13  Distrib 8.0.45, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: safedocs
-- ------------------------------------------------------
-- Server version	8.0.45

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `UserID` bigint DEFAULT NULL,
  `Name` text,
  `Email` text,
  `ContactNumber` text,
  `Age` bigint DEFAULT NULL,
  `RoleID` bigint DEFAULT NULL,
  `OrganizationID` bigint DEFAULT NULL,
  `AccountStatus` text,
  KEY `idx_users_org_role_status` (`OrganizationID`,`RoleID`,`AccountStatus`(10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `documents`
--

DROP TABLE IF EXISTS `documents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `documents` (
  `DocID` bigint DEFAULT NULL,
  `DocName` text,
  `DocSize` bigint DEFAULT NULL,
  `NumberOfPages` bigint DEFAULT NULL,
  `FilePath` text,
  `ConfidentialityLevel` text,
  `IsPasswordProtected` tinyint(1) DEFAULT NULL,
  `OwnerUserID` bigint DEFAULT NULL,
  `OrganizationID` bigint DEFAULT NULL,
  `CreatedAt` datetime DEFAULT NULL,
  `LastModifiedAt` datetime DEFAULT NULL,
  KEY `idx_documents_org_lastmodified` (`OrganizationID`,`LastModifiedAt`),
  KEY `idx_documents_owner_lastmodified` (`OwnerUserID`,`LastModifiedAt`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permissions`
--

DROP TABLE IF EXISTS `permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permissions` (
  `PermissionID` bigint DEFAULT NULL,
  `DocID` bigint DEFAULT NULL,
  `UserID` bigint DEFAULT NULL,
  `AccessType` text,
  `GrantedAt` datetime DEFAULT NULL,
  KEY `idx_permissions_user_doc_access` (`UserID`,`DocID`,`AccessType`(10)),
  KEY `idx_permissions_doc_access` (`DocID`,`AccessType`(10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `logs`
--

DROP TABLE IF EXISTS `logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `logs` (
  `LogID` bigint DEFAULT NULL,
  `UserID` bigint DEFAULT NULL,
  `DocID` bigint DEFAULT NULL,
  `ActionType` text,
  `ActionTimestamp` datetime DEFAULT NULL,
  `IPAddress` text,
  KEY `idx_logs_user_time` (`UserID`,`ActionTimestamp`),
  KEY `idx_logs_doc_action_time` (`DocID`,`ActionType`(10),`ActionTimestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `versions`
--

DROP TABLE IF EXISTS `versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `versions` (
  `VersionID` bigint DEFAULT NULL,
  `DocID` bigint DEFAULT NULL,
  `VersionNumber` bigint DEFAULT NULL,
  `ModifiedByUserID` bigint DEFAULT NULL,
  `ModifiedAt` datetime DEFAULT NULL,
  `ChangeSummary` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `passwords`
--

DROP TABLE IF EXISTS `passwords`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `passwords` (
  `ProtectionID` bigint DEFAULT NULL,
  `DocID` bigint DEFAULT NULL,
  `PasswordHash` text,
  `EncryptionMethod` text,
  `LastUpdatedAt` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `userpasswords`
--

DROP TABLE IF EXISTS `userpasswords`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `userpasswords` (
  `id` int NOT NULL AUTO_INCREMENT,
  `UserID` int NOT NULL,
  `LoginUsername` varchar(80) NOT NULL,
  `PasswordHash` varchar(255) NOT NULL,
  `IsActive` tinyint(1) NOT NULL,
  `CreatedAt` datetime NOT NULL DEFAULT (now()),
  `LastModifiedAt` datetime NOT NULL DEFAULT (now()),
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_UserPasswords_LoginUsername` (`LoginUsername`),
  UNIQUE KEY `ix_UserPasswords_UserID` (`UserID`),
  KEY `ix_UserPasswords_IsActive` (`IsActive`)
) ENGINE=InnoDB AUTO_INCREMENT=1005 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `docpasswords`
--

DROP TABLE IF EXISTS `docpasswords`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `docpasswords` (
  `id` int NOT NULL AUTO_INCREMENT,
  `DocID` int NOT NULL,
  `PasswordHash` varchar(255) NOT NULL,
  `CreatedAt` datetime NOT NULL DEFAULT (now()),
  `LastModifiedAt` datetime NOT NULL DEFAULT (now()),
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_DocPasswords_DocID` (`DocID`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `document_tags`
--

DROP TABLE IF EXISTS `document_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `document_tags` (
  `DocID` bigint DEFAULT NULL,
  `TagID` bigint DEFAULT NULL,
  `OrgID` bigint DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-04-17 16:35:45
