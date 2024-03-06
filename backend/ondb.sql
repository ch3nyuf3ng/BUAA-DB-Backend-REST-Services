DELIMITER //
CREATE FUNCTION CalculateStudentGPA(student_id VARCHAR(50)) RETURNS float
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
END //
DELIMITER ;


DELIMITER //
CREATE PROCEDURE IncreaseCTLEnrollCount(IN ctl_id INT)
BEGIN
    UPDATE courseteacherlink
    SET enroll_count = enroll_count + 1
    WHERE id = ctl_id;
END //
DELIMITER ;


DELIMITER //
CREATE PROCEDURE DecreaseCTLEnrollCount(IN ctl_id INT)
BEGIN
    UPDATE courseteacherlink
    SET enroll_count = enroll_count - 1
    WHERE id = ctl_id;
END // 
DELIMITER ;


DELIMITER //
CREATE TRIGGER AfterCreateEnrollment
AFTER INSERT
ON courseenrollment FOR EACH ROW
BEGIN
    DECLARE ctl_id INT;

    SET ctl_id = NEW.course_teacher_link_id;

    CALL IncreaseCTLEnrollCount(ctl_id);
END //
DELIMITER ;


DELIMITER //
CREATE TRIGGER AfterDropEnrollment
AFTER DELETE
ON courseenrollment FOR EACH ROW
BEGIN
    DECLARE ctl_id INT;

    SET ctl_id = OLD.course_teacher_link_id;

    CALL DecreaseCTLEnrollCount(ctl_id);
END //
DELIMITER ;

