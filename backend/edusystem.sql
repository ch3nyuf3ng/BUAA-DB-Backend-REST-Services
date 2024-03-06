/*
 Navicat MySQL Data Transfer

 Source Server         : EduSystem
 Source Server Type    : MySQL
 Source Server Version : 80035 (8.0.35-0ubuntu0.22.04.1)
 Source Host           : localhost:3306
 Source Schema         : edusystem

 Target Server Type    : MySQL
 Target Server Version : 80035 (8.0.35-0ubuntu0.22.04.1)
 File Encoding         : 65001

 Date: 24/12/2023 18:19:53
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for college
-- ----------------------------
DROP TABLE IF EXISTS `college`;
CREATE TABLE `college` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `disabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_college_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=42 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for course
-- ----------------------------
DROP TABLE IF EXISTS `course`;
CREATE TABLE `course` (
  `name` varchar(255) NOT NULL,
  `sub_category_id` int DEFAULT NULL,
  `college_id` int DEFAULT NULL,
  `credit` decimal(3,1) NOT NULL,
  `description` varchar(1000) DEFAULT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `disabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sub_category_id` (`sub_category_id`),
  KEY `college_id` (`college_id`),
  CONSTRAINT `course_ibfk_2` FOREIGN KEY (`sub_category_id`) REFERENCES `coursesubcategory` (`id`),
  CONSTRAINT `course_ibfk_3` FOREIGN KEY (`college_id`) REFERENCES `college` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for courseenrollment
-- ----------------------------
DROP TABLE IF EXISTS `courseenrollment`;
CREATE TABLE `courseenrollment` (
  `course_teacher_link_id` int NOT NULL,
  `student_id` varchar(255) NOT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `grade` decimal(4,1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `course_teacher_link_id` (`course_teacher_link_id`),
  KEY `student_id` (`student_id`),
  CONSTRAINT `courseenrollment_ibfk_1` FOREIGN KEY (`course_teacher_link_id`) REFERENCES `courseteacherlink` (`id`),
  CONSTRAINT `courseenrollment_ibfk_2` FOREIGN KEY (`student_id`) REFERENCES `student` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for coursemaincategory
-- ----------------------------
DROP TABLE IF EXISTS `coursemaincategory`;
CREATE TABLE `coursemaincategory` (
  `name` varchar(255) NOT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `disabled` tinyint(1) NOT NULL,
  `allow_enrollment` tinyint(1) NOT NULL,
  `allow_drop` tinyint(1) NOT NULL,
  `allow_set_grade` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_coursemaincategory_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for courseschedule
-- ----------------------------
DROP TABLE IF EXISTS `courseschedule`;
CREATE TABLE `courseschedule` (
  `course_teacher_link_id` int NOT NULL,
  `location` varchar(255) NOT NULL,
  `weekday` int NOT NULL,
  `course_start_time` int NOT NULL,
  `time_duration` int NOT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  KEY `course_teacher_link_id` (`course_teacher_link_id`),
  CONSTRAINT `courseschedule_ibfk_1` FOREIGN KEY (`course_teacher_link_id`) REFERENCES `courseteacherlink` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for coursesubcategory
-- ----------------------------
DROP TABLE IF EXISTS `coursesubcategory`;
CREATE TABLE `coursesubcategory` (
  `name` varchar(255) NOT NULL,
  `main_category_id` int DEFAULT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `disabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_coursesubcategory_name` (`name`),
  KEY `main_category_id` (`main_category_id`),
  CONSTRAINT `coursesubcategory_ibfk_1` FOREIGN KEY (`main_category_id`) REFERENCES `coursemaincategory` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for courseteacherlink
-- ----------------------------
DROP TABLE IF EXISTS `courseteacherlink`;
CREATE TABLE `courseteacherlink` (
  `course_id` int NOT NULL,
  `teacher_id` varchar(255) NOT NULL,
  `year` int NOT NULL,
  `start_week` int DEFAULT NULL,
  `end_week` int DEFAULT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `disabled` tinyint(1) NOT NULL,
  `enroll_limit` int NOT NULL,
  `enroll_count` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `course_id` (`course_id`),
  KEY `teacher_id` (`teacher_id`),
  CONSTRAINT `courseteacherlink_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `course` (`id`),
  CONSTRAINT `courseteacherlink_ibfk_2` FOREIGN KEY (`teacher_id`) REFERENCES `teacher` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for major
-- ----------------------------
DROP TABLE IF EXISTS `major`;
CREATE TABLE `major` (
  `name` varchar(255) NOT NULL,
  `college_id` int DEFAULT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `disabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_major_name` (`name`),
  KEY `ix_major_college_id` (`college_id`),
  CONSTRAINT `major_ibfk_1` FOREIGN KEY (`college_id`) REFERENCES `college` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for post
-- ----------------------------
DROP TABLE IF EXISTS `post`;
CREATE TABLE `post` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `created_time` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `post_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for reply
-- ----------------------------
DROP TABLE IF EXISTS `reply`;
CREATE TABLE `reply` (
  `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `post_id` int NOT NULL,
  `ref_reply_id` int DEFAULT NULL,
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` varchar(255) NOT NULL,
  `created_time` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `post_id` (`post_id`),
  KEY `ref_reply_id` (`ref_reply_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `reply_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `post` (`id`),
  CONSTRAINT `reply_ibfk_2` FOREIGN KEY (`ref_reply_id`) REFERENCES `reply` (`id`),
  CONSTRAINT `reply_ibfk_3` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for schoolclass
-- ----------------------------
DROP TABLE IF EXISTS `schoolclass`;
CREATE TABLE `schoolclass` (
  `id` int NOT NULL AUTO_INCREMENT,
  `year` int NOT NULL,
  `college_id` int DEFAULT NULL,
  `disabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_schoolclass_college_id` (`college_id`),
  CONSTRAINT `schoolclass_ibfk_1` FOREIGN KEY (`college_id`) REFERENCES `college` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=214112 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for student
-- ----------------------------
DROP TABLE IF EXISTS `student`;
CREATE TABLE `student` (
  `major_id` int DEFAULT NULL,
  `class_id` int DEFAULT NULL,
  `id` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_student_class_id` (`class_id`),
  KEY `ix_student_major_id` (`major_id`),
  CONSTRAINT `student_ibfk_2` FOREIGN KEY (`major_id`) REFERENCES `major` (`id`),
  CONSTRAINT `student_ibfk_3` FOREIGN KEY (`class_id`) REFERENCES `schoolclass` (`id`),
  CONSTRAINT `student_ibfk_4` FOREIGN KEY (`id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for teacher
-- ----------------------------
DROP TABLE IF EXISTS `teacher`;
CREATE TABLE `teacher` (
  `college_id` int DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `id` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `college_id` (`college_id`),
  CONSTRAINT `teacher_ibfk_1` FOREIGN KEY (`college_id`) REFERENCES `college` (`id`),
  CONSTRAINT `teacher_ibfk_2` FOREIGN KEY (`id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` varchar(32) NOT NULL,
  `name` varchar(16) NOT NULL,
  `birthday` date DEFAULT NULL,
  `gender` enum('male','female') DEFAULT NULL,
  `group` enum('admin','student','teacher') NOT NULL,
  `hashed_password` varchar(255) NOT NULL,
  `avatar_filename` varchar(255) DEFAULT NULL,
  `disabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Function structure for CalculateStudentGPA
-- ----------------------------
DROP FUNCTION IF EXISTS `CalculateStudentGPA`;
delimiter ;;
CREATE FUNCTION `CalculateStudentGPA`(student_id VARCHAR(50))
 RETURNS float
  READS SQL DATA 
BEGIN
    DECLARE total_grade_points FLOAT DEFAULT 0;
    DECLARE total_credits FLOAT DEFAULT 0;
    DECLARE student_gpa FLOAT;

    -- 计算学生的总课程学分绩点和总绩点
    SELECT
        SUM(
            CASE WHEN ce.grade >= 60
                THEN course.credit * (4 - 3 * (100 - ce.grade) * (100 - ce.grade) / 1600)
            ELSE 0
            END
        ),
        SUM(
            CASE WHEN ce.grade IS NOT NULL THEN course.credit
            ELSE 0
            END
        )
    INTO total_grade_points, total_credits
    FROM courseenrollment ce
    INNER JOIN courseteacherlink ctl ON ce.course_teacher_link_id = ctl.id
    INNER JOIN course ON ctl.course_id = course.id
    WHERE ce.student_id = student_id;

    -- 计算 GPA
    IF total_credits > 0 THEN
        SET student_gpa = total_grade_points / total_credits;
    ELSE
        SET student_gpa = 0;
    END IF;

    RETURN student_gpa;
END
;;
delimiter ;

-- ----------------------------
-- Procedure structure for DecreaseCTLEnrollCount
-- ----------------------------
DROP PROCEDURE IF EXISTS `DecreaseCTLEnrollCount`;
delimiter ;;
CREATE PROCEDURE `DecreaseCTLEnrollCount`(IN ctl_id INT)
BEGIN
    UPDATE courseteacherlink
    SET enroll_count = enroll_count - 1
    WHERE id = ctl_id;
END
;;
delimiter ;

-- ----------------------------
-- Procedure structure for IncreaseCTLEnrollCount
-- ----------------------------
DROP PROCEDURE IF EXISTS `IncreaseCTLEnrollCount`;
delimiter ;;
CREATE PROCEDURE `IncreaseCTLEnrollCount`(IN ctl_id INT)
BEGIN
    UPDATE courseteacherlink
    SET enroll_count = enroll_count + 1
    WHERE id = ctl_id;
END
;;
delimiter ;

-- ----------------------------
-- Triggers structure for table courseenrollment
-- ----------------------------
DROP TRIGGER IF EXISTS `AfterCreateEnrollment`;
delimiter ;;
CREATE TRIGGER `AfterCreateEnrollment` AFTER INSERT ON `courseenrollment` FOR EACH ROW BEGIN
    DECLARE ctl_id INT;

    SET ctl_id = NEW.course_teacher_link_id;

    CALL IncreaseCTLEnrollCount(ctl_id);
END
;;
delimiter ;

-- ----------------------------
-- Triggers structure for table courseenrollment
-- ----------------------------
DROP TRIGGER IF EXISTS `AfterDropEnrollment`;
delimiter ;;
CREATE TRIGGER `AfterDropEnrollment` AFTER DELETE ON `courseenrollment` FOR EACH ROW BEGIN
    DECLARE ctl_id INT;

    SET ctl_id = OLD.course_teacher_link_id;

    CALL DecreaseCTLEnrollCount(ctl_id);
END
;;
delimiter ;

SET FOREIGN_KEY_CHECKS = 1;
