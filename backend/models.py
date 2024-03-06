from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Optional
from zoneinfo import ZoneInfo

from sqlmodel import (
    Field, # type: ignore
    Relationship, # type: ignore
    SQLModel
)


def get_china_datetime() -> datetime:
    return datetime.now(ZoneInfo('Asia/Shanghai'))


class Group(str, Enum):
    admin = "管理员"
    student = "学生"
    teacher = "老师"


class Gender(str, Enum):
    male = "男"
    female = "女"


class Grade(str, Enum):
    bachelor_one = "大一"
    bachelor_two = "大二"
    bachelor_three = "大三"
    bachelor_four = "大四"
    master_one = "研一"
    master_two = "研二"
    master_three = "研三"
    doctor_one = "博一"
    doctor_two = "博二"
    doctor_three = "博三"


class UserBase(SQLModel):
    id: str = Field(primary_key=True, max_length=32)
    name: str = Field(min_length=1, max_length=16)
    birthday: Optional[date] = None
    gender: Optional[Gender] = None
    group: Group


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=32)


class UserUpdate(SQLModel):
    name: Optional[str] = Field(default=None, max_length=16)
    birthday: Optional[date] = None
    gender: Optional[Gender] = None


class User(UserBase, table=True):
    hashed_password: str
    avatar_filename: Optional[str] = None
    disabled: bool = False
    student: Optional["Student"] = Relationship(
        back_populates="user", 
        sa_relationship_kwargs={"cascade": "all, delete, delete-orphan"}
    )
    teacher: Optional["Teacher"] = Relationship(
        back_populates="user", 
        sa_relationship_kwargs={"cascade": "all, delete, delete-orphan"}
    )
    posts: list["Post"] = Relationship(
        back_populates="user", 
        sa_relationship_kwargs={"cascade": "all, delete, delete-orphan"}
    )
    replies: list["Reply"] = Relationship(
        back_populates="user", 
        sa_relationship_kwargs={"cascade": "all, delete, delete-orphan"}
    )


class UserRead(UserBase):
    disabled: bool
    
    @staticmethod
    def read(user: User) -> "UserRead":
        return UserRead.from_orm(user)


class UserReadList(SQLModel):
    total_count: int
    user_read_list: list[UserRead]


class AdminSetup(SQLModel):
    id: str
    password: str = Field(min_length=8, max_length=32)
    name: str = Field(min_length=1, max_length=16)
    gender: Optional[Gender]
    bithday: Optional[date]


class CollegeBase(SQLModel):
    id: int = Field(primary_key=True)
    name: str = Field(index=True, unique=True)


class CollegeCreate(CollegeBase):
    pass


class College(CollegeBase, table=True):
    disabled: bool = False
    majors: list["Major"] = Relationship(
        back_populates="college",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    school_classes: list["SchoolClass"] = Relationship(
        back_populates="college",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    teachers: list["Teacher"] = Relationship(back_populates="college")
    courses: list["Course"] = Relationship(back_populates="college")
    
    @staticmethod
    def create(college_create: CollegeCreate) -> "College":
        return College.from_orm(college_create)


class CollegeUpdate(SQLModel):
    name: Optional[str] = None


class CollegeRead(CollegeBase):
    disabled: bool = False
    
    @staticmethod
    def read(college: College) -> "CollegeRead":
        return CollegeRead.from_orm(college)


class CollegeReadList(SQLModel):
    total_count: int
    college_read_list: list[CollegeRead]


class MajorBase(SQLModel):
    name: str = Field(index=True)
    college_id: int = Field(foreign_key="college.id", index=True)


class MajorCreate(MajorBase):
    pass


class Major(MajorBase, table=True):
    id: Optional[int] = Field(primary_key=True)
    disabled: bool = False
    college: College = Relationship(back_populates="majors")
    students: list["Student"] = Relationship(
        back_populates="major",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    
    @staticmethod
    def create(major_create: MajorCreate) -> "Major":
        return Major.from_orm(major_create)


class MajorRead(MajorBase):
    id: int
    disabled: bool
    
    @staticmethod
    def read(major: Major) -> "MajorRead":
        return MajorRead.from_orm(major)


class MajorReadList(SQLModel):
    total_count: int
    major_read_list: list[MajorRead]


class MajorUpdate(SQLModel):
    name: Optional[str] = None
    college_id: Optional[int] = None


class SchoolClassBase(SQLModel):
    id: int = Field(primary_key=True)
    year: int = Field(ge=1952)
    college_id: Optional[int] = Field(
        default=None, foreign_key="college.id", index=True
    )


class SchoolClassCreate(SchoolClassBase):
    pass


class SchoolClass(SchoolClassBase, table=True):
    disabled: bool = False
    college: College = Relationship(back_populates="school_classes")
    students: "Student" = Relationship(back_populates="school_class")
    
    @staticmethod
    def create(school_class_create: SchoolClassCreate) -> "SchoolClass":
        return SchoolClass.from_orm(school_class_create)


class SchoolClassRead(SchoolClassBase):
    disabled: bool
    
    @staticmethod
    def read(school_class: SchoolClass) -> "SchoolClassRead":
        return SchoolClassRead.from_orm(school_class)


class SchoolClassUpdate(SQLModel):
    year: Optional[int] = Field(default=None, ge=1952)
    college_id: Optional[int] = None


class SchoolClassReadList(SQLModel):
    total_count: int
    school_class_read_list: list[SchoolClassRead]


class StudentBase(SQLModel):
    major_id: int = Field(foreign_key="major.id", index=True)
    class_id: int = Field(foreign_key="schoolclass.id", index=True)


class StudentCreate(StudentBase):
    pass


class Student(StudentBase, table=True):
    id: str = Field(primary_key=True, foreign_key="user.id")
    major: Major = Relationship(back_populates="students")
    school_class: SchoolClass = Relationship(back_populates="students")
    course_enrollments: list["CourseEnrollment"] = Relationship(
        back_populates="student", 
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    user: User = Relationship(
        back_populates="student",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    
    @staticmethod
    def create(student_id: str, student_create: StudentCreate) -> "Student":
        setting_dict = student_create.dict()
        setting_dict.update({"id": student_id})
        return Student.parse_obj(setting_dict)


class StudentUpdate(SQLModel):
    # name: Optional[str] = Field(default=None, min_length=1)
    major_id: Optional[int] = None
    class_id: Optional[int] = None


class StudentRead(StudentBase):
    id: str
    college_id: int
    
    @staticmethod
    def read(student: Student) -> "StudentRead":
        college_id = student.major.college_id
        student_dict = student.dict()
        student_dict.update({"college_id": college_id})
        return StudentRead.parse_obj(student_dict)


class StudentReadList(SQLModel):
    total_count: int
    student_read_list: list[StudentRead]


class TeacherBase(SQLModel):
    college_id: Optional[int] = Field(foreign_key="college.id")
    description: Optional[str] = Field(default=None)


class TeacherCreate(TeacherBase):
    pass


class Teacher(TeacherBase, table=True):
    id: str = Field(primary_key=True, foreign_key="user.id")
    college: Optional[College] = Relationship(back_populates="teachers")
    course_teacher_links: list["CourseTeacherLink"] = Relationship(
        back_populates="teacher", 
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    user: User = Relationship(
        back_populates="teacher",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    
    @staticmethod
    def create(teacher_id: str, teacher_create: TeacherCreate) -> "Teacher":
        setting_dict = teacher_create.dict()
        setting_dict.update({"id": teacher_id})
        return Teacher.parse_obj(setting_dict)


class TeacherUpdate(SQLModel):
    college_id: Optional[int] = None
    description: Optional[str] = None


class TeacherRead(TeacherBase):
    id: str
    
    @staticmethod
    def read(teacher: Teacher) -> "TeacherRead":
        return TeacherRead.from_orm(teacher)


class TeacherReadList(SQLModel):
    total_count: int
    teacher_read_list: list[TeacherRead]


class CourseMainCategoryBase(SQLModel):
    name: str = Field(index=True, unique=True)


class CourseMainCategoryCreate(CourseMainCategoryBase):
    pass


class CourseMainCategoryUpdate(SQLModel):
    name: Optional[str] = Field(default=None, min_length=1)
    allow_enrollment: Optional[bool] = None
    allow_drop: Optional[bool] = None
    allow_set_grade: Optional[bool] = None


class CourseMainCategory(CourseMainCategoryBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    disabled: bool = False
    allow_enrollment: bool = False
    allow_drop: bool = False
    allow_set_grade: bool = False
    sub_categories: list["CourseSubCategory"] = Relationship(
        back_populates="main_category"
    )
    
    @staticmethod
    def create(category_create: CourseMainCategoryCreate) -> "CourseMainCategory":
        return CourseMainCategory.from_orm(category_create)


class CourseMainCategoryRead(CourseMainCategoryBase):
    id: int
    disabled: bool
    allow_enrollment: bool
    allow_drop: bool
    allow_set_grade: bool
    
    @staticmethod
    def read(category: CourseMainCategory) -> "CourseMainCategoryRead":
        return CourseMainCategoryRead.from_orm(category)


class CourseMainCategoryReadList(SQLModel):
    total_count: int
    category_list: list[CourseMainCategoryRead]


class CourseSubCategoryBase(SQLModel):
    name: str = Field(index=True, unique=True, min_length=1)
    main_category_id: int = Field(foreign_key="coursemaincategory.id")


class CourseSubCategoryCreate(CourseSubCategoryBase):
    pass


class CourseSubCategoryUpdate(SQLModel):
    name: Optional[str] = Field(default=None, min_length=1)
    main_category_id: Optional[int] = Field(default=None)


class CourseSubCategory(CourseSubCategoryBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    disabled: bool = False
    main_category: CourseMainCategory = Relationship(
        back_populates="sub_categories"
    )
    courses: list["Course"] = Relationship(back_populates="sub_category")
    
    @staticmethod
    def create(category_create: CourseSubCategoryCreate) -> "CourseSubCategory":
        return CourseSubCategory.from_orm(category_create)


class CourseSubCategoryRead(CourseSubCategoryBase):
    id: int
    disabled: bool
    
    @staticmethod
    def read(category: CourseSubCategory) -> "CourseSubCategoryRead":
        return CourseSubCategoryRead.from_orm(category)


class CourseSubCategoryReadList(SQLModel):
    total_count: int
    category_list: list[CourseSubCategoryRead]


class CourseBase(SQLModel):
    name: str = Field(min_length=1)
    # main_category_id: Optional[int] = Field(
    #     default=None, foreign_key="coursemaincategory.id"
    # )
    sub_category_id: int = Field(foreign_key="coursesubcategory.id")
    college_id: Optional[int] = Field(default=None, foreign_key="college.id")
    credit: Decimal = Field(max_digits=3, decimal_places=1)
    description: Optional[str] = Field(default=None, max_length=1000)


class CourseCreate(CourseBase):
    pass


class CourseUpdate(SQLModel):
    name: Optional[str] = Field(default=None, min_length=1)
    # main_category_id: Optional[int] = None
    sub_category_id: Optional[int] = None
    college_id: Optional[int] = None
    credit: Optional[Decimal] = Field(default=None, max_digits=3, decimal_places=1)
    description: Optional[str] = Field(default=None, max_length=1000)


class Course(CourseBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    disabled: bool = False
    # main_category: Optional[CourseMainCategory] = Relationship(back_populates="courses")
    sub_category: CourseSubCategory = Relationship(back_populates="courses")
    college: Optional[College] = Relationship(back_populates="courses")
    course_teacher_links: list["CourseTeacherLink"] = Relationship(
        back_populates="course", 
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    
    @staticmethod
    def create(course_create: CourseCreate) -> "Course":
        return Course.from_orm(course_create)


class CourseRead(CourseBase):
    id: int
    main_category_id: int
    disabled: bool
    
    @staticmethod
    def read(course: Course) -> "CourseRead":
        main_category_id = course.sub_category.main_category_id
        course_dict = course.dict()
        course_dict.update({"main_category_id": main_category_id})
        return CourseRead.parse_obj(course_dict)


class CourseReadList(SQLModel):
    total_count: int
    course_read_list: list[CourseRead]


class CourseTeacherLinkBase(SQLModel):
    course_id: int = Field(foreign_key="course.id")
    teacher_id: str = Field(foreign_key="teacher.id")
    year: int = Field(ge=1952)
    start_week: Optional[int] = Field(default=None, ge=1, le=18)
    end_week: Optional[int] = Field(default=None, ge=1, le=18)
    enroll_limit: int = Field(ge=1)


class CourseTeacherLinkCreate(CourseTeacherLinkBase):
    pass


class CourseTeacherLinkUpdate(CourseTeacherLinkBase):
    pass


class CourseTeacherLink(CourseTeacherLinkBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    disabled: bool = False
    enroll_count: int = 0
    course: Course = Relationship(back_populates="course_teacher_links")
    teacher: Teacher = Relationship(back_populates="course_teacher_links")
    course_enrollments: list["CourseEnrollment"] = Relationship(
        back_populates="course_teacher_link", 
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    schedules: list["CourseSchedule"] = Relationship(
        back_populates="course_teacher_link", 
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    
    @staticmethod
    def create(link_create: CourseTeacherLinkCreate) -> "CourseTeacherLink":
        return CourseTeacherLink.from_orm(link_create)


class CourseTeacherLinkRead(CourseTeacherLinkBase):
    id: int
    disabled: bool
    enroll_count: int
    
    @staticmethod
    def read(link: CourseTeacherLink) -> "CourseTeacherLinkRead":
        return CourseTeacherLinkRead.from_orm(link)


class CourseTeacherLinkReadList(SQLModel):
    total_count: int
    link_read_list: list[CourseTeacherLinkRead]


class CourseTeacherLinkDetailRead(CourseTeacherLinkBase):
    id: int
    disabled: bool
    enroll_count: int
    course: Optional[CourseRead] = None
    teacher: Optional[TeacherRead] = None
    schedules: list["CourseSchedule"]
    
    @staticmethod
    def read(link: CourseTeacherLink) -> "CourseTeacherLinkDetailRead":
        return CourseTeacherLinkDetailRead.from_orm(link)


class CourseEnrollmentBase(SQLModel):
    course_teacher_link_id: int = Field(foreign_key="courseteacherlink.id")
    student_id: str = Field(foreign_key="student.id")


class CourseEnrollmentCreate(CourseEnrollmentBase):
    pass


class CourseEnrollmentUpdate(SQLModel):
    grade: Decimal = Field(max_digits=4, decimal_places=1, ge=0, le=100)


class CourseEnrollment(CourseEnrollmentBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    grade: Optional[Decimal] = Field(default=None, max_digits=4, decimal_places=1, ge=0, le=100)
    course_teacher_link: CourseTeacherLink = Relationship(
        back_populates="course_enrollments"
    )
    student: Student = Relationship(back_populates="course_enrollments")
    
    @staticmethod
    def create(enrollment_create: CourseEnrollmentCreate) -> "CourseEnrollment":
        return CourseEnrollment.from_orm(enrollment_create)
    

class CourseEnrollmentRead(CourseEnrollmentBase):
    id: int
    grade: Optional[Decimal] = None
    
    @staticmethod
    def read(enrollment: CourseEnrollment) -> "CourseEnrollmentRead":
        return CourseEnrollmentRead.from_orm(enrollment)


class CourseEnrollmentReadList(SQLModel):
    total_count: int
    enrollment_read_list: list[CourseEnrollmentRead]


class CourseScheduleBase(SQLModel):
    course_teacher_link_id: int = Field(foreign_key="courseteacherlink.id")
    location: str
    weekday: int = Field(ge=1, le=7)
    course_start_time: int = Field(ge=1, le=14)
    time_duration: int = Field(ge=1)
    
    
class CourseScheduleCreate(CourseScheduleBase):
    pass


class CourseScheduleModify(CourseScheduleBase):
    pass


class CourseSchedule(CourseScheduleBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    course_teacher_link: Optional[CourseTeacherLink] = Relationship(
        back_populates="schedules"
    )
    
    @staticmethod
    def create(schedule_create: CourseScheduleCreate) -> "CourseSchedule":
        return CourseSchedule.from_orm(schedule_create)


class CourseScheduleRead(CourseScheduleBase):
    id: int
    
    @staticmethod
    def read(schedule: CourseSchedule) -> "CourseScheduleRead":
        return CourseScheduleRead.from_orm(schedule)


class CourseScheduleReadList(SQLModel):
    total_count: int
    schedule_read_list: list[CourseScheduleRead]


class PostBase(SQLModel):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(min_length=1)
    content: str = Field(min_length=1, max_length=65535)
    user_id: str = Field(foreign_key="user.id")
    created_time: datetime = Field(default_factory=get_china_datetime, nullable=False)


class PostCreate(SQLModel):
    title: str = Field(min_length=1)
    content: str = Field(min_length=1)
    

class Post(PostBase, table=True):
    user: User = Relationship(back_populates="posts")
    replies: list["Reply"] = Relationship(
        back_populates="post",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )


class PostRead(PostBase):
    @staticmethod
    def read(post: Post) -> "PostRead":
        return PostRead.from_orm(post)


class PostReadList(SQLModel):
    total_count: int
    post_read_list: list[PostRead]


class ReplyBase(SQLModel):
    content: str = Field(min_length=1, max_length=65535)
    post_id: int = Field(foreign_key="post.id")
    ref_reply_id: Optional[int] = Field(foreign_key="reply.id")
    
    
class ReplyCreate(ReplyBase):
    pass


class Reply(ReplyBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="user.id")
    created_time: datetime = Field(default_factory=get_china_datetime, nullable=False)
    user: User = Relationship(back_populates="replies")
    post: Post = Relationship(back_populates="replies")
    
    
class ReplyRead(ReplyBase):
    id: int
    user_id: str = Field(foreign_key="user.id")
    created_time: datetime
    
    @staticmethod
    def read(reply: Reply) -> "ReplyRead":
        return ReplyRead.from_orm(reply)
    
    
class ReplyReadList(SQLModel):
    total_count: int
    reply_read_list: list[ReplyRead]
    
    
class UserCreateBundle(SQLModel):
    user_create: UserCreate
    student_create: Optional[StudentCreate]
    teacher_create: Optional[TeacherCreate]
    
    
class UserReadBundle(SQLModel):
    user_read: UserRead
    student_read: Optional[StudentRead]
    teacher_read: Optional[TeacherRead]
    
    
class StudentGPARead(SQLModel):
    gpa: float


User.update_forward_refs(Student=Student, Teacher=Teacher, Post=Post)
College.update_forward_refs(
    Major=Major,
    SchoolClass=SchoolClass,
    Student=Student,
    Teacher=Teacher,
    Course=Course,
)
Major.update_forward_refs(Student=Student)
SchoolClass.update_forward_refs(Student=Student)
Teacher.update_forward_refs(CourseTeacherLink=CourseTeacherLink)
CourseMainCategory.update_forward_refs(
    CourseSubCategory=CourseSubCategory, Course=Course
)
CourseSubCategory.update_forward_refs(Course=Course)
CourseTeacherLink.update_forward_refs(CourseSchedule=CourseSchedule)
CourseTeacherLinkRead.update_forward_refs(CourseSchedule=CourseSchedule)
CourseTeacherLinkDetailRead.update_forward_refs(CourseSchedule=CourseSchedule)
Course.update_forward_refs(
    CourseTeacherLink=CourseTeacherLink, CourseEnrollment=CourseEnrollment
)
Post.update_forward_refs(Reply=Reply)
Reply.update_forward_refs(Reply=Reply)

