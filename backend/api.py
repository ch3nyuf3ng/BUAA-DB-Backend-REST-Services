from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager # type: ignore
from datetime import date, datetime, timedelta
from enum import Enum
import os
from typing import Annotated, Any, Optional
from uuid import uuid4


from fastapi import (
    Depends, 
    FastAPI,
    File,
    HTTPException, 
    Query,
    status as HTTPStatus,
    UploadFile
)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import FileResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.security import (
    OAuth2PasswordBearer, 
    OAuth2PasswordRequestForm
)
from pydantic import BaseModel, Field
from sqlalchemy import func, text
from sqlmodel import (
    Session, 
    col, 
    or_, 
    select
)
from jose import JWTError
from jose.jwt import (
    encode as jwt_encode, 
    decode as jwt_decode
)
from passlib.context import CryptContext

from .models import (
    College, 
    CollegeCreate, 
    CollegeRead, 
    CollegeReadList, 
    CollegeUpdate, 
    Course, 
    CourseCreate,
    CourseEnrollment,
    CourseEnrollmentCreate,
    CourseEnrollmentRead,
    CourseEnrollmentReadList,
    CourseEnrollmentUpdate, 
    CourseMainCategory, 
    CourseMainCategoryCreate, 
    CourseMainCategoryRead, 
    CourseMainCategoryReadList,
    CourseMainCategoryUpdate, 
    CourseRead, 
    CourseReadList,
    CourseSchedule,
    CourseScheduleCreate,
    CourseScheduleModify,
    CourseScheduleRead,
    CourseScheduleReadList, 
    CourseSubCategory, 
    CourseSubCategoryCreate, 
    CourseSubCategoryRead, 
    CourseSubCategoryReadList, 
    CourseSubCategoryUpdate,
    CourseTeacherLink,
    CourseTeacherLinkCreate,
    CourseTeacherLinkDetailRead, 
    CourseTeacherLinkRead,
    CourseTeacherLinkReadList,
    CourseTeacherLinkUpdate,
    CourseUpdate, 
    Gender, 
    Group, 
    Major, 
    MajorCreate, 
    MajorRead, 
    MajorReadList, 
    MajorUpdate, 
    Post,
    PostCreate,
    PostRead, 
    PostReadList,
    Reply,
    ReplyCreate,
    ReplyRead,
    ReplyReadList, 
    SchoolClass, 
    SchoolClassCreate, 
    SchoolClassRead, 
    SchoolClassReadList, 
    SchoolClassUpdate, 
    Student, 
    StudentCreate,
    StudentGPARead, 
    StudentRead, 
    StudentReadList, 
    StudentUpdate, 
    Teacher, 
    TeacherCreate, 
    TeacherRead, 
    TeacherReadList, 
    TeacherUpdate, 
    User,
    UserCreateBundle, 
    UserRead,
    UserReadBundle, 
    UserReadList, 
    UserUpdate
)
# from .database import create_db_and_tables
from .database import engine


class AdminSetup(BaseModel):
    id: str
    password: str = Field(min_length=8, max_length=32)
    name: str = Field(min_length=1, max_length=16)
    gender: Optional[Gender]
    bithday: Optional[date]


class Tag(str, Enum):
    default = "Default"
    security = "Security"
    users = "Users"
    colleges = "Colleges"
    majors = "Majors"
    classes = "Classes"
    students = "Students"
    teachers = "Teachers"
    course_main_categories = "Course Main Categories"
    course_sub_categories = "Course Sub Categories"
    courses = "Courses"
    course_teacher_links = "Course Teacher Links"
    course_enrollments = "Course Enrollments"
    course_schedules = "Course Schedules"
    posts = "Posts"
    replies = "Replies"


class TagMetadata(BaseModel):
    name: Tag
    description: str


class TokenType(str, Enum):
    bearer = "Bearer"


class Token(BaseModel):
    access_token: str
    token_type: TokenType
    
    
class PasswordUpdate(BaseModel):
    password: Annotated[str, Field(min_length=8, max_length=32)]
    

class SuccessResponse(BaseModel):
    success: bool
    

class HTTPExceptionResponse(BaseModel):
    detail: Any
    
    
GENERAL_RESPONSE_MODEL_SETTING = {
    "model": HTTPExceptionResponse
}


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
with open('backend/secret_key.txt', 'r', encoding='utf-8') as file:
    SECRET_KEY = file.read()
SETUP_ADMIN_FILE_PATH = 'backend/setup_admin.json'
AVATAR_FILE_PATH = 'backend/static/avatars'
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png"}


def custom_generate_unique_id(route: APIRoute) -> str:
    return f"{route.tags[0]}-{route.name}"


@asynccontextmanager
async def lifespan(api: FastAPI) -> AsyncGenerator[Any, None]:
    # create_db_and_tables()
    setup_admin(SETUP_ADMIN_FILE_PATH)
    yield


def setup_admin(setup_file_path: str) -> None:
    session = Session(engine)
    try:
        admin_setup = AdminSetup.parse_file(setup_file_path)
        admin_user = session.get(User, admin_setup.id)
        if admin_user is None:
            user_dict = admin_setup.dict(exclude={"password"})
            user_dict.update({
                "hashed_password": get_hashed_password(admin_setup.password),
                "group": Group.admin.value
            })
            admin_user = User.parse_obj(user_dict)
            session.add(admin_user)
            session.commit()
    except Exception as e:
        print(e)
        print("Unable to setup an admin.")
    finally:
        session.close()


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

api = FastAPI(
    lifespan=lifespan, 
    generate_unique_id_function=custom_generate_unique_id,
    title="教务选课系统API",
    version="0.1.0",
    redoc_url=None
)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "https://api.ch3nyuf3ng.me"
]

api.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def responses_of(*args: int | str) -> dict[int | str, dict[str, type]]:
    return {arg : GENERAL_RESPONSE_MODEL_SETTING for arg in args}


def get_database_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


def generate_unique_filename(original_filename: str) -> str:
    extension = original_filename.split('.')[-1]
    unique_filename = f"{uuid4()}.{extension}"
    return unique_filename


def password_is_correct(password: str, hashed_password: str) -> bool:
    return password_context.verify(password, hashed_password)


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def authenticate_user(
    username: str, 
    password: str
) -> Optional[User]:
    for session in get_database_session():
        user = session.get(User, username)
        if user is not None and password_is_correct(password, user.hashed_password):
            return user
        return None


def create_encoded_jwt(
    payload: dict[str, Any], 
    expires_delta: timedelta | None = None
) -> str:
    to_encode = payload.copy()
    if expires_delta is not None:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt_encode(
        to_encode, 
        key=SECRET_KEY, 
        algorithm=ALGORITHM
    )
    return encoded_jwt


def get_current_user(
    encoded_jwt: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_database_session)]
) -> User:
    credentials_exception = HTTPException(
        status_code=HTTPStatus.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt_decode(
            token=encoded_jwt, 
            key=SECRET_KEY, 
            algorithms=[ALGORITHM]
        )
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = session.get(User, username)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if current_user.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_401_UNAUTHORIZED,
            detail="Disabled user."
        )
    return current_user


@api.get(
    "/", 
    status_code=HTTPStatus.HTTP_307_TEMPORARY_REDIRECT, 
    summary="跳转文档页", 
    tags=[Tag.default]
)
async def redirect_docs() -> RedirectResponse:
    return RedirectResponse("/docs")


@api.post(
    "/token", 
    response_model=Token,
    responses=responses_of(HTTPStatus.HTTP_401_UNAUTHORIZED),
    summary="登录获取令牌",
    tags=[Tag.security]
)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_encoded_jwt(
        payload={"sub": user.id}, 
        expires_delta=access_token_expires
    )
    return Token(
        access_token=access_token, 
        token_type=TokenType.bearer
    )


@api.post(
    "/users", 
    status_code=HTTPStatus.HTTP_201_CREATED,
    response_model=UserReadBundle,
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="创建用户",
    description=
"""
仅管理员可创建用户，创建后的用户默认为激活状态。

若创建老师或学生类别的用户，需要提供相关的信息。

成功创建用户后返回创建好的用户信息。
""",
    tags=[Tag.users]
)
async def create_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_user: UserCreateBundle
) -> UserReadBundle:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_user = session.get(User, new_user.user_create.id)
    if existed_user is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid user id. Exists a user who has the same id."
        )
    if new_user.user_create.group is Group.student and new_user.student_create is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="No new student data within this request."
        )            
    if new_user.user_create.group is Group.teacher and new_user.teacher_create is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="No new teacher data within this request."
        )
    plain_password = new_user.user_create.password
    user_dict = new_user.user_create.dict(exclude={"password"})
    user_dict.update({"hashed_password": get_hashed_password(plain_password)})
    print(user_dict)
    db_user = User.parse_obj(user_dict)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    user_read = UserRead.read(db_user)
    student_read = None
    teacher_read = None
    if db_user.group is Group.student:
        assert new_user.student_create is not None
        try:
            student_read = await create_student(
                student_id=db_user.id,
                current_user=current_user,
                session=session,
                new_student=new_user.student_create
            )
        except Exception as e:
            await delete_user(
                user_id=db_user.id,
                current_user=current_user,
                session=session
            )
            raise e
    elif db_user.group is Group.teacher:
        assert new_user.teacher_create is not None
        try:
            teacher_read = await create_teacher(
                teacher_id=db_user.id,
                current_user=current_user,
                session=session,
                new_teacher=new_user.teacher_create
            )
        except Exception as e:
            await delete_user(
                user_id=db_user.id,
                current_user=current_user,
                session=session
            )
            raise e
    return UserReadBundle(
        user_read=user_read, 
        student_read=student_read, 
        teacher_read=teacher_read
    )


@api.get(
    "/users", 
    response_model=UserReadList,
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN
    ),
    summary="获取用户列表",
    description=
"""
仅管理员可获取用户列表。

管理员可以查看包含已禁用的用户的列表，但需要设置。
""",
    tags=[Tag.users]
)
async def read_users(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> UserReadList:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied."
        )
    count_query = select(func.count(User.id))
    user_list_query = select(User)
    if only_active:
        count_query = count_query.where(User.disabled == False)
        user_list_query = user_list_query.where(User.disabled == False)
    count = session.exec(count_query).one()
    db_users = session.exec(user_list_query.offset(offset).limit(limit)).all()
    user_read_list = [UserRead.read(db_user) for db_user in db_users]
    return UserReadList(total_count=count, user_read_list=user_read_list)


@api.get(
    "/users/{user_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=UserRead, 
    summary="获取单个用户信息",
    description=
"""
任何用户都可以根据用户 ID 获取单个用户的一般信息。
""",
    tags=[Tag.users]
)
async def read_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> UserRead:
    db_user = session.get(User, user_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="User not found."
    )
    if db_user is None:
        raise exception
    return UserRead.read(db_user)


@api.get(
    "/users/{user_id}/bundle", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=UserReadBundle, 
    summary="获取打包的单个用户信息",
    description=
"""
任何用户都可以根据用户 ID 获取单个用户的一般信息。返回包含用户相关的学生/老师信息
""",
    tags=[Tag.users]
)
async def read_user_bundle(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> UserReadBundle:
    db_user = session.get(User, user_id)
    user_not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="User not found."
    )
    user_info_broken_exception = HTTPException(
        status_code=HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="User info is broken."
    )
    if db_user is None:
        raise user_not_found_exception
    user_read = UserRead.read(db_user)
    student_read = None
    teacher_read = None
    if db_user.group is Group.student:
        db_student = db_user.student
        if db_student is None:
            raise user_info_broken_exception
        student_read = StudentRead.read(db_student)
    elif db_user.group is Group.teacher:
        db_teacher = db_user.teacher
        if db_teacher is None:
            raise user_info_broken_exception
        teacher_read = TeacherRead.read(db_teacher)
    return UserReadBundle(
        user_read=user_read, 
        student_read=student_read, 
        teacher_read=teacher_read
    )


@api.patch(
    "/users/{user_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=UserRead, 
    summary="更新一般用户信息",
    description=
"""
允许管理员根据用户 ID 更新对应用户的一般信息，包括生日、姓名、性别。

发送的 JSON 可以只包含要更新的键值对。

管理员可以更新已被禁用的用户，但需要设置，且设置仅对管理员用户生效。
""",
    tags=[Tag.users]
)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> UserRead:
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not an administrator or the user to be updated."
    )
    if current_user.group is not Group.admin:
        raise permission_exception
    db_user = session.get(User, user_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="User not found."
    )
    if db_user is None:
        raise not_found_exception
    if only_active and db_user.disabled:
        raise not_found_exception
    user_change = user_update.dict(exclude_unset=True)
    for key, value in user_change.items():
        setattr(db_user, key, value)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return UserRead.read(db_user)


@api.delete(
    "/users/{user_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=SuccessResponse, 
    summary="彻底删除用户",
    description=
"""
允许管理员根据用户 ID 彻底删除用户，包含已被禁用的用户。

    警告：
    
    删除一个学生用户会导致其学生附属的信息、选课记录、发帖及回复被删除。
    删除一个老师用户会导致其附属的信息、属于该老师的课程的选课记录与课程安排、发帖及回复均被删除。
    
    此操作不可逆。
""",
    tags=[Tag.users]
)
async def delete_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    if current_user.id == user_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You cannot delete yourself."
        )
    db_user = session.get(User, user_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="User not found."
    )
    if db_user is None:
        raise not_found_exception
    if db_user.avatar_filename is not None:
        await delete_user_avatar(user_id, current_user, session)
    session.delete(db_user)
    session.commit()
    return SuccessResponse(success=True)


@api.put(
    "/users/{user_id}/avatar",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=SuccessResponse,
    summary="上传用户头像",
    description=
"""
允许管理员根据用户 ID 或者一般用户用自己的 ID 上传头像，允许 JPG(JPEG) 和 PNG 两种格式。
""",
    tags=[Tag.users]
)
async def upload_user_avatar(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    avatar_image_file: Annotated[UploadFile, File(description="User's avatar image file")]
) -> SuccessResponse:
    if current_user.group is not Group.admin and current_user.id != user_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not the user of the id or an administrator."
        )
    db_user = session.get(User, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    if avatar_image_file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid file type"
        )
    if db_user.avatar_filename is not None:
        old_avatar_filename = db_user.avatar_filename
        old_avatar_file_path = f"{AVATAR_FILE_PATH}/{old_avatar_filename}"
        if os.path.exists(old_avatar_file_path):
            os.remove(old_avatar_file_path)
    assert avatar_image_file.filename is not None
    unique_filename = generate_unique_filename(avatar_image_file.filename)
    file_location = f"{AVATAR_FILE_PATH}/{unique_filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(avatar_image_file.file.read())
    db_user.avatar_filename = unique_filename
    session.add(db_user)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/users/{user_id}/avatar",
    responses={
        HTTPStatus.HTTP_200_OK: {
            "content": { "image/png": {}, "image/jpeg": {} },
            "description": "Return the avatar as image/png or image/jpeg."
        },
        HTTPStatus.HTTP_401_UNAUTHORIZED: { "model" : HTTPExceptionResponse},
        HTTPStatus.HTTP_404_NOT_FOUND: { "model" : HTTPExceptionResponse}
    },
    summary="查看用户头像",
    description=
"""
允许任何用户查看某个用户 ID 对应的未被禁用的用户头像。

若用户未设置头像，则返回默认的头像。
""",
    tags=[Tag.users]
)
async def read_user_avatar(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> FileResponse:
    db_user = session.get(User, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    default_avatar = FileResponse(
        path=f"{AVATAR_FILE_PATH}/default.png",
        media_type='image/png'
    )
    if db_user.avatar_filename is None:
        return default_avatar
    filename = db_user.avatar_filename
    file_path = f"{AVATAR_FILE_PATH}/{filename}"
    if os.path.exists(file_path):
        return FileResponse(path=file_path)
    else:
        db_user.avatar_filename = None
        session.add(db_user)
        session.commit()
        return default_avatar


@api.delete(
    "/users/{user_id}/avatar",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="删除用户头像",
    description=
"""
允许某个用户 ID 对应的用户本人或管理员删除用户头像。

头像被删除后，查看用户头像将返回默认头像。
""",
    response_model=SuccessResponse,
    tags=[Tag.users]
)
async def delete_user_avatar(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin and current_user.id != user_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not the user of the id or an administrator."
        )
    db_user = session.get(User, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    if db_user.avatar_filename is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="User avatar does not exist."
        )
    filename = db_user.avatar_filename
    file_path = f"{AVATAR_FILE_PATH}/{filename}"
    if os.path.exists(file_path):
        os.remove(file_path)
    db_user.avatar_filename = None
    session.add(db_user)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/users/{user_id}/disable", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="禁用用户",
    description=
"""
允许管理员禁用用户 ID 对应的某个用户。

禁用用户后用户将无法再登录并访问 API，但是与用户相关信息会被保留。
""",
    response_model=SuccessResponse, 
    tags=[Tag.users]
)
async def disable_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    if current_user.id == user_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You cannot disable yourself."
        )
    db_user = session.get(User, user_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="User not found."
    )
    if db_user is None:
        raise not_found_exception
    if db_user.disabled:
        raise not_found_exception
    db_user.disabled = True
    session.add(db_user)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/users/{user_id}/password", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=SuccessResponse, 
    summary="修改用户密码",
    description=
"""
允许管理员或用户本人修改密码。
""",
    tags=[Tag.users]
)
async def update_user_password(
    user_id: str,
    new_password: PasswordUpdate,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin and current_user.id != user_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator or the user to be updated."
        )
    db_user = session.get(User, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    db_user.hashed_password = get_hashed_password(new_password.password)
    session.add(db_user)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/users/{user_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=SuccessResponse,
    summary="激活（取消禁用）用户",
    description=
"""
允许管理员激活（取消禁用）用户 ID 对应的某个用户。
""",
    tags=[Tag.users]
)
async def activate_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_user = session.get(User, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    if not db_user.disabled:
        return SuccessResponse(success=True)
    db_user.disabled = False
    session.add(db_user)
    session.commit()
    return SuccessResponse(success=True)
    

@api.get(
    "/users/{user_id}/posts", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=PostReadList, 
    summary="获取用户帖子",
    description=
"""
允许任何用户查看某个未被禁用的用户的帖子。

允许管理员查看被禁用的用户的帖子。
""",
    tags=[Tag.users]
)
async def read_user_posts(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> PostReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="User not found."
    )
    user = session.get(User, user_id)
    if user is None:
        raise exception
    if user.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Post.id))
        .where(col(Post.user_id) == user_id)
    ).one()
    user_posts = session.exec(
        select(Post)
        .where(col(Post.user_id) == user_id)
        .offset(offset).limit(limit)
    ).all()
    post_read_list = [PostRead.read(post) for post in user_posts]
    return PostReadList(total_count=count, post_read_list=post_read_list)


@api.get(
    "/search/users", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN
    ),
    response_model=UserReadList, 
    summary="搜索用户",
    description=
"""
允许管理员或者老师按照姓名、性别、权限、学院号来查找用户（学生、老师、管理员）。

查找已禁用的用户仅对管理员生效。
""",
    tags=[Tag.users]
)
def search_users(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    name: Annotated[Optional[str], Query(min_length=1, max_length=50)] = None,
    gender: Optional[Gender] = None,
    group: Optional[Group] = None,
    college_id: Optional[int] = None,
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> UserReadList:
    if current_user.group not in [Group.admin, Group.teacher]:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission forbidden. You're not an administrator or a teacher."
        )
    count_query = (select(func.count(User.id))
                   .join(Student, isouter=True)
                   .join(SchoolClass, isouter=True)
                   .join(Teacher, isouter=True))
    user_list_query = (select(User)
                       .join(Student, isouter=True)
                       .join(SchoolClass, isouter=True)
                       .join(Teacher, isouter=True))
    if name is not None:
        count_query = count_query.where(col(User.name).contains(name))
        user_list_query = user_list_query.where(col(User.name).contains(name))
    if gender is not None:
        count_query = count_query.where(User.gender == gender)
        user_list_query = user_list_query.where(User.gender == gender)
    if group is not None:
        count_query = count_query.where(User.group == group)
        user_list_query = user_list_query.where(User.group == group)
    if college_id is not None:
        count_query = count_query.where(or_(
            SchoolClass.college_id == college_id, 
            Teacher.college_id == college_id
        ))
        user_list_query = user_list_query.where(or_(
            SchoolClass.college_id == college_id, 
            Teacher.college_id == college_id
        ))
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(User.disabled == False)
        user_list_query = user_list_query.where(User.disabled == False)
    count = session.exec(count_query).one()
    user_list = session.exec(user_list_query.offset(offset).limit(limit)).all()
    user_read_list = [UserRead.read(user) for user in user_list]
    return UserReadList(total_count=count, user_read_list=user_read_list)
    

@api.post(
    "/colleges", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT,
    ),
    response_model=CollegeRead, 
    status_code=HTTPStatus.HTTP_201_CREATED,
    summary="创建学院",
    description=
"""
允许管理员创建学院。
""",
    tags=[Tag.colleges]
)
async def create_college(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_college: CollegeCreate
) -> CollegeRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_college = session.get(College, new_college.id)
    if existed_college is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid college id. Exists a college who has the same id."
        )
    same_name_college = session.exec(
        select(College)
        .where(College.disabled == False)
        .where(College.name == new_college.name)
    ).first()
    if same_name_college is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid college name. Exists a college who has the same name."
        )
    db_college = College.create(new_college)
    session.add(db_college)
    session.commit()
    session.refresh(db_college)
    return CollegeRead.read(db_college)


@api.get(
    "/colleges", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    response_model=CollegeReadList, 
    summary="获取学院列表",
    description=
"""
允许任何用户获取所有学院信息。

获取已被禁用的学院仅对管理员生效。
""",
    tags=[Tag.colleges],
)
async def read_colleges(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CollegeReadList:
    count_query = select(func.count(College.id))
    college_list_query = select(College)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(College.disabled == False)
        college_list_query = college_list_query.where(College.disabled == False)
    count = session.exec(count_query).one()
    db_colleges = session.exec(college_list_query.offset(offset).limit(limit)).all()
    college_read_list = [CollegeRead.read(college) for college in db_colleges]
    return CollegeReadList(total_count=count, college_read_list=college_read_list)


@api.get(
    "/colleges/{college_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=CollegeRead, 
    summary="获取单个学院信息",
    description=
"""
允许任何用户获取单个学院信息。

仅允许管理员获取已被禁用的学院信息。
""",
    tags=[Tag.colleges]
)
async def read_college(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CollegeRead:
    db_college = session.get(College, college_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    if db_college is None:
        raise exception
    if db_college.disabled and current_user.group is not Group.admin:
        raise exception
    return CollegeRead.read(db_college)


@api.patch(
    "/colleges/{college_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=CollegeRead, 
    summary="修改单个学院信息",
    description=
"""
允许管理员修改单个学院信息。
""",
    tags=[Tag.colleges]
)
async def update_college(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    college_update: CollegeUpdate
) -> CollegeRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_college = session.get(College, college_id)
    if db_college is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="College not found."
        )
    if college_update.name is not None:
        same_name_college = session.exec(
            select(College)
            .where(College.disabled == False)
            .where(col(College.id) != college_id)
            .where(College.name == college_update.name)
        ).first()
        if same_name_college is not None:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_409_CONFLICT,
                detail="Invalid college name. Exists a college with different id who has the same name."
            )
    college_changes = college_update.dict(exclude_unset=True)
    for key, value in college_changes.items():
        setattr(db_college, key, value)
    session.add(db_college)
    session.commit()
    session.refresh(db_college)
    return CollegeRead.read(db_college)


@api.delete(
    "/colleges/{college_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=SuccessResponse,
    summary="删除单个学院",
    description=
"""
允许管理员删除单个学院。

    警告：
    
    会删除与之关联的专业、班级、学生、老师、课程。
    请在删除前考虑将关联的专业、班级、学生、老师、课程的学院号更新。
    或者考虑禁用单个学院。
    
    此操作不可逆。
""",
    tags=[Tag.colleges]
)
async def delete_college(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_college = session.get(College, college_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    if db_college is None:
        raise not_found_exception
    session.delete(db_college)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/colleges/{college_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=SuccessResponse,
    summary="禁用单个学院",
    description=
"""
允许管理员禁用单个学院。
""",
    tags=[Tag.colleges]
)
async def disable_college(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_college = session.get(College, college_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    if db_college is None:
        raise not_found_exception
    if db_college.disabled:
        raise not_found_exception
    db_college.disabled = True
    session.add(db_college)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/colleges/{college_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=SuccessResponse,
    summary="取消禁用单个学院",
    description=
"""
允许管理员取消禁用单个学院。
""",
    tags=[Tag.colleges]
)
async def activate_college(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_college = session.get(College, college_id)
    if db_college is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="College not found."
        )
    if not db_college.disabled:
        return SuccessResponse(success=True)
    same_name_college = session.exec(
        select(College)
        .where(College.disabled == False)
        .where(College.name == db_college.name)
    ).first()
    if same_name_college is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Exists an active college who has the same name."
        )
    db_college.disabled = False
    session.add(db_college)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/colleges/{college_id}/majors", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    response_model=MajorReadList, 
    summary="查询某个学院的专业",
    tags=[Tag.colleges]
)
async def read_college_majors(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> MajorReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    college = session.get(College, college_id)
    if college is None:
        raise exception
    if college.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Major.id))
        .where(col(Major.college_id) == college_id)
    ).one()
    college_majors = session.exec(
        select(Major)
        .where(col(Major.college_id) == college_id)
        .offset(offset).limit(limit)
    ).all()
    major_read_list = [MajorRead.read(major) for major in college_majors]
    return MajorReadList(total_count=count, major_read_list=major_read_list)


@api.get(
    "/colleges/{college_id}/classes", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="查询某个学院的班级",
    response_model=SchoolClassReadList, 
    tags=[Tag.colleges]
)
async def read_college_classes(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> SchoolClassReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    college = session.get(College, college_id)
    if college is None:
        raise exception
    if college.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(SchoolClass.id))
        .where(col(SchoolClass.college_id) == college_id)
    ).one()
    college_classes = session.exec(
        select(SchoolClass)
        .where(col(SchoolClass.college_id) == college_id)
        .offset(offset).limit(limit)
    ).all()
    school_class_read_list = [SchoolClassRead.read(college_class) for college_class in college_classes]
    return SchoolClassReadList(total_count=count, school_class_read_list=school_class_read_list)


@api.get(
    "/colleges/{college_id}/students", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="查询某个学院的学生",
    response_model=StudentReadList, 
    tags=[Tag.colleges]
)
async def read_college_students(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> StudentReadList:
    if current_user.group not in [Group.admin, Group.teacher]:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator or a teacher."
        )
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    college = session.get(College, college_id)
    if college is None:
        raise not_found_exception
    if college.disabled and current_user.group is not Group.admin:
        raise not_found_exception
    count = session.exec(
        select(func.count(Student.id))
        .join(SchoolClass)
        .where(col(SchoolClass.college_id) == college_id)
    ).one()
    college_students = session.exec(
        select(Student)
        .join(SchoolClass)
        .where(col(SchoolClass.college_id) == college_id)
        .offset(offset).limit(limit)
    ).all()
    student_read_list = [StudentRead.read(student) for student in college_students]
    return StudentReadList(total_count=count, student_read_list=student_read_list)


@api.get(
    "/colleges/{college_id}/teachers", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="查询某个学院的老师",
    response_model=TeacherReadList, 
    tags=[Tag.colleges]
)
async def read_college_teachers(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> TeacherReadList:
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    college = session.get(College, college_id)
    if college is None:
        raise not_found_exception
    if college.disabled and current_user.group is not Group.admin:
        raise not_found_exception
    count = session.exec(
        select(func.count(Teacher.id))
        .where(col(Teacher.college_id) == college_id)
    ).one()
    college_teachers = session.exec(
        select(Teacher)
        .where(col(Teacher.college_id) == college_id)
        .offset(offset).limit(limit)
    ).all()
    teacher_read_list = [TeacherRead.read(teacher) for teacher in college_teachers]
    return TeacherReadList(total_count=count, teacher_read_list=teacher_read_list)


@api.get(
    "/colleges/{college_id}/courses", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="查询某个学院的课程",
    response_model=CourseReadList, 
    tags=[Tag.colleges]
)
async def read_college_courses(
    college_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseReadList:
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="College not found."
    )
    college = session.get(College, college_id)
    if college is None:
        raise not_found_exception
    if college.disabled and current_user.group is not Group.admin:
        raise not_found_exception
    count = session.exec(
        select(func.count(Course.id))
        .where(col(Course.college_id) == college_id)
    ).one()
    college_courses = session.exec(
        select(Course)
        .where(col(Course.college_id) == college_id)
        .offset(offset).limit(limit)
    ).all()
    course_read_list = [CourseRead.read(course) for course in college_courses]
    return CourseReadList(total_count=count, course_read_list=course_read_list)


@api.get(
    "/search/colleges", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="搜索某个学院",
    description="根据名字查询",
    response_model=CollegeReadList, 
    tags=[Tag.colleges]
)
async def search_colleges(
    name: Annotated[str, Query(min_length=1, max_length=50)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CollegeReadList:
    count_query = select(func.count(College.id)).where(col(College.name).contains(name))
    college_list_query = select(College).where(col(College.name).contains(name))
    if only_active or current_user is not Group.admin:
        count_query = count_query.where(College.disabled == False)
        college_list_query = college_list_query.where(College.disabled == False)
    count = session.exec(count_query).one()
    db_colleges = session.exec(college_list_query.offset(offset).limit(limit)).all()
    college_read_list = [CollegeRead.read(college) for college in db_colleges]
    return CollegeReadList(total_count=count, college_read_list=college_read_list)


@api.post(
    "/majors",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=MajorRead,
    summary="创建一个专业",
    tags=[Tag.majors]
)
async def create_major(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_major: MajorCreate
) -> MajorRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    same_name_major = session.exec(
        select(Major)
        .where(Major.disabled == False)
        .where(Major.name == new_major.name)
    ).first()
    if same_name_major is not None and same_name_major.college_id == new_major.college_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid major name. Exists a major which has the same name and the same college id."
        )
    existed_college = session.get(College, new_major.college_id)
    if existed_college is None or existed_college.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid college id."
        )
    db_major = Major.create(new_major)
    session.add(db_major)
    session.commit()
    session.refresh(db_major)
    return MajorRead.read(db_major)


@api.get(
    "/majors",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取专业列表",
    response_model=MajorReadList,
    tags=[Tag.majors]
)
async def read_majors(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> MajorReadList:
    count_query = select(func.count(Major.id))
    major_list_query = select(Major)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(Major.disabled == False)
        major_list_query = major_list_query.where(Major.disabled == False)
    count = session.exec(count_query).one()
    db_majors = session.exec(major_list_query.offset(offset).limit(limit)).all()
    major_read_list = [MajorRead.read(major) for major in db_majors]
    return MajorReadList(total_count=count, major_read_list=major_read_list)


@api.get(
    "/majors/{major_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个专业信息",
    response_model=MajorRead,
    tags=[Tag.majors]
)
async def read_major(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> MajorRead:
    db_major = session.get(Major, major_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Major not found."
    )
    if db_major is None:
        raise exception
    if db_major.disabled and current_user.group is not Group.admin:
        raise exception
    return MajorRead.read(db_major)


@api.patch(
    "/majors/{major_id}",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="修改单个专业信息",
    response_model=MajorRead,
    tags=[Tag.majors]
)
async def update_major(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    major_new: MajorUpdate
) -> MajorRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_major = session.get(Major, major_id)
    if db_major is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Major not found."
        )
    if major_new.name is not None:
        same_name_major = session.exec(
            select(Major)
            .where(Major.name == major_new.name)
            .where(col(Major.id) != major_id)
            .where(Major.disabled == False)
        ).first()
        if same_name_major is not None:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_409_CONFLICT,
                detail="Invalid major name. Exists a major who has the same name."
            )
    if major_new.college_id is not None:
        existed_college = session.get(College, major_new.college_id)
        if existed_college is None or existed_college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Invalid college id."
            )
    major_change = major_new.dict(exclude_unset=True)
    for key, value in major_change.items():
        setattr(db_major, key, value)
    session.add(db_major)
    session.commit()
    session.refresh(db_major)
    return MajorRead.read(db_major)


@api.delete(
    "/majors/{major_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个专业",
    description=
"""
允许管理员删除单个专业。

    警告：

    会导致专业相关的学生被删除。
""",
    response_model=SuccessResponse,
    tags=[Tag.majors]
)
async def delete_major(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_major = session.get(Major, major_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Major not found."
    )
    if db_major is None:
        raise not_found_exception
    session.delete(db_major)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/majors/{major_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="禁用某个专业",
    response_model=SuccessResponse,
    tags=[Tag.majors]
)
async def disable_major(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_major = session.get(Major, major_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Major not found."
    )
    if db_major is None:
        raise not_found_exception
    if db_major.disabled:
        raise not_found_exception
    db_major.disabled = True
    session.add(db_major)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/majors/{major_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=SuccessResponse,
    summary="激活某个专业",
    tags=[Tag.majors]
)
async def activate_major(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_major = session.get(Major, major_id)
    if db_major is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Major not found."
        )
    if not db_major.disabled:
        return SuccessResponse(success=True)
    same_name_major = session.exec(
        select(Major)
        .where(Major.disabled == False)
        .where(Major.name == db_major.name)
    ).first()
    if same_name_major is not None and same_name_major.college_id == db_major.college_id:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid major name. Exists a major which has the same name and the same college id."
        )
    db_major.disabled = False
    session.add(db_major)
    session.commit()
    return SuccessResponse(success=True)
    

@api.get(
    "/majors/{major_id}/college",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=CollegeRead,
    summary="获取某个专业对应的学院",
    tags=[Tag.majors]
)
async def read_major_college(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CollegeRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Major not found."
    )
    db_major = session.get(Major, major_id)
    if db_major is None:
        raise exception
    if db_major.disabled and current_user.group is not Group.admin:
        raise exception
    return CollegeRead.read(db_major.college)


@api.get(
    "/majors/{major_id}/students",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=StudentReadList,
    summary="获取某个专业的学生。",
    tags=[Tag.majors]
)
async def read_major_students(
    major_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> StudentReadList:
    if current_user.group not in [Group.admin, Group.teacher]:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator or a teacher."
        )
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Major not found."
    )
    major = session.get(Major, major_id)
    if major is None:
        raise exception
    if major.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Student.id))
        .where(col(Student.major_id) == major_id)
    ).one()
    major_students = session.exec(
        select(Student)
        .where(col(Student.major_id) == major_id)
        .offset(offset).limit(limit)
    ).all()
    student_read_list = [StudentRead.read(student) for student in major_students]
    return StudentReadList(total_count=count, student_read_list=student_read_list)


@api.get(
    "/search/majors",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    response_model=MajorReadList,
    summary="根据名字搜索专业",
    tags=[Tag.majors]
)
async def search_majors(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    name: Annotated[str, Query(min_length=1, max_length=50)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> MajorReadList:
    count_query = select(func.count(Major.id)).where(col(Major.name).contains(name))
    major_list_query = select(Major).where(col(Major.name).contains(name))
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(Major.disabled == False)
        major_list_query = major_list_query.where(Major.disabled == False)
    count = session.exec(count_query).one()
    major_list = session.exec(major_list_query.offset(offset).limit(limit)).all()
    major_read_list = [MajorRead.read(major) for major in major_list]
    return MajorReadList(total_count=count, major_read_list=major_read_list)


@api.post(
    "/classes", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=SchoolClassRead, 
    summary="创建一个班级",
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.classes]
)
async def create_class(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_class: SchoolClassCreate
) -> SchoolClassRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_class = session.get(SchoolClass, new_class.id)
    if existed_class is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid class id. Exists a class who has the same id."
        )
    if new_class.college_id is not None:
        existed_college = session.get(College, new_class.college_id)
        if existed_college is None or existed_college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Invalid college id."
            )
    db_class = SchoolClass.create(new_class)
    session.add(db_class)
    session.commit()
    session.refresh(db_class)
    return SchoolClassRead.read(db_class)


@api.get(
    "/classes", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    response_model=SchoolClassReadList, 
    summary="获取班级列表",
    tags=[Tag.classes],
)
async def read_classes(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> SchoolClassReadList:
    count_query = select(func.count(SchoolClass.id))
    class_list_query = select(SchoolClass)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(SchoolClass.disabled == False)
        class_list_query = class_list_query.where(SchoolClass.disabled == False)
    count = session.exec(count_query).one()
    db_classes = session.exec(class_list_query.offset(offset).limit(limit)).all()
    school_class_read_list = [SchoolClassRead.read(school_class) for school_class in db_classes]
    return SchoolClassReadList(total_count=count, school_class_read_list=school_class_read_list)


@api.get(
    "/classes/{class_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=SchoolClassRead, 
    summary="获取单个班级信息",
    tags=[Tag.classes]
)
async def read_class(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SchoolClassRead:
    db_class = session.get(SchoolClass, class_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Class not found."
    )
    if db_class is None:
        raise exception
    if db_class.disabled and current_user.group is not Group.admin:
        raise exception
    return SchoolClassRead.read(db_class)


@api.patch(
    "/classes/{class_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=SchoolClassRead, 
    summary="修改单个班级信息",
    tags=[Tag.classes]
)
async def update_class(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    class_update: SchoolClassUpdate
) -> SchoolClassRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_class = session.get(SchoolClass, class_id)
    if db_class is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Class not found."
        )
    if class_update.college_id is not None:
        existed_college = session.get(College, class_update.college_id)
        if existed_college is None or existed_college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Invalid college id."
            )
    class_changes = class_update.dict(exclude_unset=True)
    for key, value in class_changes.items():
        setattr(db_class, key, value)
    session.add(db_class)
    session.commit()
    session.refresh(db_class)
    return SchoolClassRead.read(db_class)


@api.delete(
    "/classes/{class_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=SuccessResponse,
    summary="删除单个班级",
    tags=[Tag.classes]
)
async def delete_class(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_class = session.get(SchoolClass, class_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Class not found."
    )
    if db_class is None:
        raise not_found_exception
    session.delete(db_class)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/classes/{class_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="禁用单个班级",
    response_model=SuccessResponse,
    tags=[Tag.classes]
)
async def disable_class(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_class = session.get(SchoolClass, class_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Class not found."
    )
    if db_class is None:
        raise not_found_exception
    if db_class.disabled:
        raise not_found_exception
    db_class.disabled = True
    session.add(db_class)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/classes/{class_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=SuccessResponse,
    summary="取消禁用班级",
    tags=[Tag.classes]
)
async def activate_class(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_class = session.get(SchoolClass, class_id)
    if db_class is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Class not found."
        )
    if not db_class.disabled:
        return SuccessResponse(success=True)
    db_class.disabled = False
    session.add(db_class)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/classes/{class_id}/college",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=CollegeRead,
    summary="获取单个班级对应的学院",
    tags=[Tag.classes]
)
async def read_class_college(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CollegeRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Class not found."
    )
    db_class = session.get(SchoolClass, class_id)
    if db_class is None:
        raise exception
    if db_class.disabled and current_user.group is not Group.admin:
        raise exception
    return CollegeRead.read(db_class.college)


@api.get(
    "/classes/{class_id}/students",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=StudentReadList,
    summary="获取单个班级的学生列表",
    tags=[Tag.classes]
)
async def read_class_students(
    class_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> StudentReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Class not found."
    )
    if current_user.group is Group.student:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not allowed to get class's student list."
        )
    school_class = session.get(SchoolClass, class_id)
    if school_class is None:
        raise exception
    if school_class.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Student.id))
        .where(col(Student.class_id) == class_id)
    ).one()
    class_students = session.exec(
        select(Student)
        .where(col(Student.class_id) == class_id)
        .offset(offset).limit(limit)
    ).all()
    student_read_list = [StudentRead.read(student) for student in class_students]
    return StudentReadList(total_count=count, student_read_list=student_read_list)


async def create_student(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_student: StudentCreate
) -> StudentRead:
    """允许管理员创建学生。
    """
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_user = session.get(User, student_id)
    if existed_user is None or existed_user.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid student id. The id is not related to an active user's id."
        )
    if existed_user.group is not Group.student:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="The related user seems not to be a student."
        )
    existed_student = session.get(Student, student_id)
    if existed_student is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid student id. Exists a student who has the same id."
        )
    existed_major = session.get(Major, new_student.major_id)
    if existed_major is None or existed_major.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid major id."
        )
    existed_class = session.get(SchoolClass, new_student.class_id)
    if existed_class is None or existed_class.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid class id."
        )
    if (existed_major.college_id != existed_class.college_id):
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Class's college id is inconsistent with Major's college id."
        )
    db_student = Student.create(student_id, new_student)
    session.add(db_student)
    session.commit()
    session.refresh(db_student)
    return StudentRead.read(db_student)


@api.get(
    "/users/{student_id}/student", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个学生的信息",
    response_model=StudentRead, 
    tags=[Tag.students]
)
async def read_student(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> StudentRead:
    db_student = session.get(Student, student_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Student not found."
    )
    if db_student is None:
        raise exception
    if db_student.user.disabled and current_user.group is not Group.admin:
        raise exception
    return StudentRead.read(db_student)


@api.patch(
    "/users/{student_id}/student", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=StudentRead, 
    summary="修改单个学生的信息",
    tags=[Tag.students]
)
async def update_student(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    student_update: StudentUpdate
) -> StudentRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_student = session.get(Student, student_id)
    if db_student is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Student not found."
        )
    existed_major = session.get(Major, student_update.major_id)
    if existed_major is None or existed_major.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid major id."
        )
    existed_class = session.get(SchoolClass, student_update.class_id)
    if existed_class is None or existed_class.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid class id."
        )
    if (existed_class.college_id != existed_major.college_id):
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Class's college id is inconsistent with major's college id."
        )
    student_changes = student_update.dict(exclude_unset=True)
    for key, value in student_changes.items():
        setattr(db_student, key, value)
    session.add(db_student)
    session.commit()
    session.refresh(db_student)
    return StudentRead.read(db_student)

 
@api.get(
    "/users/{student_id}/student/college",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个学生对应的学院的信息",
    response_model=CollegeRead,
    tags=[Tag.students]
)   
async def read_student_college(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CollegeRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Student not found."
    )
    db_student = session.get(Student, student_id)
    if db_student is None:
        raise exception
    if db_student.user.disabled and current_user.group is not Group.admin:
        raise exception
    return CollegeRead.read(db_student.school_class.college)


@api.get(
    "/users/{student_id}/student/major",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个学生对应的专业的信息",
    response_model=MajorRead,
    tags=[Tag.students]
)   
async def read_student_major(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> MajorRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Student not found."
    )
    db_student = session.get(Student, student_id)
    if db_student is None:
        raise exception
    if db_student.user.disabled and current_user.group is not Group.admin:
        raise exception
    return MajorRead.read(db_student.major)


@api.get(
    "/users/{student_id}/student/class",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个学生对应的班级信息",
    response_model=SchoolClassRead,
    tags=[Tag.students]
)   
async def read_student_class(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SchoolClassRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Student not found."
    )
    db_student = session.get(Student, student_id)
    if db_student is None:
        raise exception
    if db_student.user.disabled and current_user.group is not Group.admin:
        raise exception
    return SchoolClassRead.read(db_student.school_class)


@api.get(
    "/users/{student_id}/student/course-enrollments",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个学生的选课信息",
    response_model=CourseEnrollmentReadList,
    tags=[Tag.students]
)
async def read_student_courses(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseEnrollmentReadList:
    if current_user.group is not Group.admin:
        if current_user.id != student_id:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_403_FORBIDDEN,
                detail="Permission denied. You're not an administrator or the student itself."
            )
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Student not found."
    )
    db_student = session.get(Student, student_id)
    if db_student is None:
        raise exception
    if db_student.user.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(CourseEnrollment.id))
        .where(col(CourseEnrollment.student_id) == student_id)
    ).one()
    enrollments = session.exec(
        select(CourseEnrollment)
        .where(col(CourseEnrollment.student_id) == student_id)
        .offset(offset).limit(limit)
    ).all()
    enrollment_list = [CourseEnrollmentRead.read(enrollment) for enrollment in enrollments]
    return CourseEnrollmentReadList(total_count=count, enrollment_read_list=enrollment_list)


@api.get(
    "/users/{student_id}/student/gpa",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个学生的 GPA",
    response_model=StudentGPARead,
    tags=[Tag.students]
)
async def read_student_gpa(
    student_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> StudentGPARead:
    if current_user.group is not Group.admin:
        if current_user.id != student_id:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_403_FORBIDDEN,
                detail="Permission denied. You're not an administrator or the student itself."
            )
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Student not found."
    )
    db_student = session.get(Student, student_id)
    if db_student is None:
        raise exception
    if db_student.user.disabled and current_user.group is not Group.admin:
        raise exception
    query = text(f"SELECT CalculateStudentGPA('{student_id}') AS gpa")
    result = session.execute(query).fetchone() # type: ignore
    gpa: float = result.gpa # type: ignore
    
    return StudentGPARead(gpa=gpa)
    
    
async def create_teacher(
    teacher_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_teacher: TeacherCreate
) -> TeacherRead:
    """
    允许管理员创建老师。
    """
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_user = session.get(User, teacher_id)
    if existed_user is None or existed_user.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid teacher id. The id is not related to an active user's id."
        )
    if existed_user.group is not Group.teacher:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="The related user seems not to be a teacher."
        )
    existed_teacher = session.get(Teacher, teacher_id)
    if existed_teacher is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Invalid teacher id. Exists a teacher who has the same id."
        )
    if new_teacher.college_id is not None:
        existed_college = session.get(College, new_teacher.college_id)
        if existed_college is None or existed_college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Invalid college id."
            )
    db_teacher = Teacher.create(teacher_id, new_teacher)
    session.add(db_teacher)
    session.commit()
    session.refresh(db_teacher)
    return TeacherRead.read(db_teacher)


@api.get(
    "/users/{teacher_id}/teacher", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    response_model=TeacherRead, 
    summary="获取单个老师的信息",
    tags=[Tag.teachers]
)
async def read_teacher(
    teacher_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> TeacherRead:
    db_teacher = session.get(Teacher, teacher_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Teacher not found."
    )
    if db_teacher is None:
        raise exception
    if db_teacher.user.disabled and current_user.group is not Group.admin:
        raise exception
    return TeacherRead.read(db_teacher)


@api.patch(
    "/users/{teacher_id}/teacher", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="修改单个老师的信息",
    response_model=TeacherRead, 
    tags=[Tag.teachers]
)
async def update_teacher(
    teacher_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    teacher_update: TeacherUpdate
) -> TeacherRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_teacher = session.get(Teacher, teacher_id)
    if db_teacher is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Teacher not found."
        )
    if teacher_update.college_id is not None:
        existed_college = session.get(College, teacher_update.college_id)
        if existed_college is None or existed_college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Invalid college id."
            )
    teacher_changes = teacher_update.dict(exclude_unset=True)
    for key, value in teacher_changes.items():
        setattr(db_teacher, key, value)
    session.add(db_teacher)
    session.commit()
    session.refresh(db_teacher)
    return TeacherRead.read(db_teacher)


@api.get(
    "/users/{teacher_id}/teacher/college",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个老师的学院信息",
    response_model=CollegeRead,
    tags=[Tag.teachers]
)
async def read_teacher_college(
    teacher_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CollegeRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Teacher not found."
    )
    db_teacher = session.get(Teacher, teacher_id)
    if db_teacher is None:
        raise exception
    if db_teacher.user.disabled and current_user.group is not Group.admin:
        raise exception
    if db_teacher.college is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Teacher's college not found."
        )
    return CollegeRead.read(db_teacher.college)


@api.get(
    "/users/{teacher_id}/teacher/courses",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个老师的课程信息",
    response_model=CourseReadList,
    tags=[Tag.teachers]
)
async def read_teacher_courses(
    teacher_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Teacher not found."
    )
    db_teacher = session.get(Teacher, teacher_id)
    if db_teacher is None:
        raise exception
    if db_teacher.user.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Course.id))
        .join(CourseTeacherLink)
        .where(col(CourseTeacherLink.teacher_id) == teacher_id)
        .where(CourseTeacherLink.disabled == False)
    ).one()
    courses = session.exec(
        select(Course)
        .join(CourseTeacherLink)
        .where(col(CourseTeacherLink.teacher_id) == teacher_id)
        .where(CourseTeacherLink.disabled == False)
        .offset(offset).limit(limit)
    ).all()
    course_read_list = [CourseRead.read(course) for course in courses]
    return CourseReadList(total_count=count, course_read_list=course_read_list)


@api.get(
    "/users/{teacher_id}/teacher/course-teacher-links",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个老师的课程链接信息",
    response_model=CourseTeacherLinkReadList,
    tags=[Tag.teachers]
)   
async def read_teacher_course_teacher_links(
    teacher_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseTeacherLinkReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Teacher not found."
    )
    db_teacher = session.get(Teacher, teacher_id)
    if db_teacher is None:
        raise exception
    if db_teacher.user.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(CourseTeacherLink.id))
        .where(col(CourseTeacherLink.teacher_id) == teacher_id)
        .where(CourseTeacherLink.disabled == False)
    ).one()
    links = session.exec(
        select(CourseTeacherLink)
        .where(col(CourseTeacherLink.teacher_id) == teacher_id)
        .where(CourseTeacherLink.disabled == False)
        .offset(offset).limit(limit)
    ).all()
    link_list = [CourseTeacherLinkRead.read(link) for link in links]
    return CourseTeacherLinkReadList(total_count=count, link_read_list=link_list)


@api.post(
    "/course-main-category", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=CourseMainCategoryRead, 
    summary="创建一个课程主类别",
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.course_main_categories]
)
async def create_course_main_category(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_course_main_category: CourseMainCategoryCreate
) -> CourseMainCategoryRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_course_main_category = session.exec(
        select(CourseMainCategory)
        .where(CourseMainCategory.name == new_course_main_category.name)
    ).first()
    if existed_course_main_category is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Existed a main course category has the same name."
        )
    db_category = CourseMainCategory.create(new_course_main_category)
    session.add(db_category)
    session.commit()
    session.refresh(db_category)
    return CourseMainCategoryRead.read(db_category)


@api.get(
    "/course-main-category", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取课程主类别列表",
    response_model=CourseMainCategoryReadList, 
    tags=[Tag.course_main_categories]
)
async def read_course_main_categories(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CourseMainCategoryReadList:
    count_query = select(func.count(CourseMainCategory.id))
    category_list_query = select(CourseMainCategory)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(CourseMainCategory.disabled == False)
        category_list_query = category_list_query.where(CourseMainCategory.disabled == False)
    count = session.exec(count_query).one()
    db_categories = session.exec(category_list_query.offset(offset).limit(limit)).all()
    category_list = [CourseMainCategoryRead.read(category) for category in db_categories]
    return CourseMainCategoryReadList(total_count=count, category_list=category_list)


@api.get(
    "/course-main-category/{category_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个课程主类别信息",
    response_model=CourseMainCategoryRead, 
    tags=[Tag.course_main_categories]
)
async def read_course_main_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseMainCategoryRead:
    db_category = session.get(CourseMainCategory, category_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course main category not found."
    )
    if db_category is None:
        raise exception
    if db_category.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseMainCategoryRead.read(db_category)


@api.patch(
    "/course-main-category/{category_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="修改单个课程主类别信息",
    response_model=CourseMainCategoryRead, 
    tags=[Tag.course_main_categories]
)
async def update_course_main_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    category_update: CourseMainCategoryUpdate
) -> CourseMainCategoryRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseMainCategory, category_id)
    if db_category is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course main category not found."
        )
    if category_update.name is not None:
        same_name_active_category = session.exec(
            select(CourseMainCategory)
            .where(CourseMainCategory.name == category_update.name)
            .where(col(CourseMainCategory.id) != category_id)
            .where(CourseMainCategory.disabled == False)
        ).first()
        if same_name_active_category is not None:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_409_CONFLICT,
                detail="Existed a different active course main category which has the same."
            )
    category_changes = category_update.dict(exclude_unset=True)
    for key, value in category_changes.items():
        setattr(db_category, key, value)
    session.add(db_category)
    session.commit()
    session.refresh(db_category)
    return CourseMainCategoryRead.read(db_category)


@api.delete(
    "/course-main-category/{category_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个课程主类别信息",
    response_model=SuccessResponse,
    tags=[Tag.course_main_categories]
)
async def delete_course_main_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseMainCategory, category_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course Main Category not found."
    )
    if db_category is None:
        raise not_found_exception
    session.add(db_category)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-main-category/{category_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="禁用单个课程主类别",
    response_model=SuccessResponse,
    tags=[Tag.course_main_categories]
)
async def disable_course_main_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseMainCategory, category_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course Main Category not found."
    )
    if db_category is None:
        raise not_found_exception
    if db_category.disabled:
        raise not_found_exception
    db_category.disabled = True
    session.add(db_category)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-main-category/{category_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="取消禁用单个课程主类别",
    response_model=SuccessResponse,
    tags=[Tag.course_main_categories]
)
async def activate_course_main_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseMainCategory, category_id)
    if db_category is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course main category not found."
        )
    if not db_category.disabled:
        return SuccessResponse(success=True)
    same_name_main_category = session.exec(
        select(CourseMainCategory)
        .where(CourseMainCategory.disabled == False)
        .where(CourseMainCategory.name == db_category.name)
    ).first()
    if same_name_main_category is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Exists an active main category which has the same name."
        )
    db_category.disabled = False
    session.add(db_category)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/course-main-category/{category_id}/sub-categories", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程主类别的子类别列表",
    response_model=CourseSubCategoryReadList, 
    tags=[Tag.course_main_categories]
)
async def read_course_main_category_sub_categories(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseSubCategoryReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course main category not found."
    )
    main_category = session.get(CourseMainCategory, category_id)
    if main_category is None:
        raise exception
    if main_category.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(CourseSubCategory.id))
        .where(col(CourseSubCategory.main_category_id) == category_id)
    ).one()
    sub_categories = session.exec(
        select(CourseSubCategory)
        .where(col(CourseSubCategory.main_category_id) == category_id)
        .offset(offset).limit(limit)
    ).all()
    category_list = [CourseSubCategoryRead.read(category) for category in sub_categories]
    return CourseSubCategoryReadList(total_count=count, category_list=category_list)


@api.get(
    "/course-main-category/{category_id}/courses", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个课程主类别的课程列表",
    response_model=CourseReadList, 
    tags=[Tag.course_main_categories]
)
async def read_course_main_category_courses(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course main category not found."
    )
    main_category = session.get(CourseMainCategory, category_id)
    if main_category is None:
        raise exception
    if main_category.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Course.id))
        .join(CourseSubCategory)
        .where(col(CourseSubCategory.main_category_id) == category_id)
    ).one()
    courses = session.exec(
        select(Course)
        .join(CourseSubCategory)
        .where(col(CourseSubCategory.main_category_id) == category_id)
        .offset(offset).limit(limit)
    ).all()
    course_read_list = [CourseRead.read(course) for course in courses]
    return CourseReadList(total_count=count, course_read_list=course_read_list)


@api.post(
    "/course-sub-category", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    response_model=CourseSubCategoryRead,
    summary="创建单个课程子类别", 
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.course_sub_categories]
)
async def create_course_sub_category(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_course_sub_category: CourseSubCategoryCreate
) -> CourseSubCategoryRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_course_sub_category = session.exec(
        select(CourseSubCategory)
        .where(CourseSubCategory.name == new_course_sub_category.name)
    ).first()
    if existed_course_sub_category is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Existed a course sub category has the same name."
        )
    main_category = session.get(CourseMainCategory, new_course_sub_category.main_category_id)
    if main_category is None or main_category.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Corresponding main category doesn't exist."
        )
    db_category = CourseSubCategory.create(new_course_sub_category)
    session.add(db_category)
    session.commit()
    session.refresh(db_category)
    return CourseSubCategoryRead.read(db_category)


@api.get(
    "/course-sub-category", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取课程子类别列表",
    response_model=CourseSubCategoryReadList, 
    tags=[Tag.course_sub_categories]
)
async def read_course_sub_categories(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CourseSubCategoryReadList:
    count_query = select(func.count(CourseSubCategory.id))
    category_list_query = select(CourseSubCategory)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(CourseSubCategory.disabled == False)
        category_list_query = category_list_query.where(CourseSubCategory.disabled == False)
    count = session.exec(count_query).one()
    db_categories = session.exec(category_list_query.offset(offset).limit(limit)).all()
    category_list = [CourseSubCategoryRead.read(category) for category in db_categories]
    return CourseSubCategoryReadList(total_count=count, category_list=category_list)


@api.get(
    "/course-sub-category/{category_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程子类别的信息",
    response_model=CourseSubCategoryRead, 
    tags=[Tag.course_sub_categories]
)
async def read_course_sub_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseSubCategoryRead:
    db_category = session.get(CourseSubCategory, category_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course main category not found."
    )
    if db_category is None:
        raise exception
    if db_category.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseSubCategoryRead.read(db_category)


@api.patch(
    "/course-sub-category/{category_id}",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="修改单个课程子类别的信息",
    response_model=CourseSubCategoryRead, 
    tags=[Tag.course_sub_categories]
)
async def update_course_sub_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    category_update: CourseSubCategoryUpdate
) -> CourseSubCategoryRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseSubCategory, category_id)
    if db_category is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course sub category not found."
        )
    if category_update.name is not None:
        same_name_active_category = session.exec(
            select(CourseMainCategory)
            .where(CourseMainCategory.name == category_update.name)
            .where(col(CourseMainCategory.id) != category_id)
            .where(CourseMainCategory.disabled == False)
        ).first()
        if same_name_active_category is not None:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_409_CONFLICT,
                detail="Existed a different active course main category which has the same."
            )
    if category_update.main_category_id is not None:
        main_category = session.get(CourseMainCategory, category_update.main_category_id)
        if main_category is None or main_category.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Corresponding main category doesn't exist."
            )
    category_changes = category_update.dict(exclude_unset=True)
    for key, value in category_changes.items():
        setattr(db_category, key, value)
    session.add(db_category)
    session.commit()
    session.refresh(db_category)
    return CourseSubCategoryRead.read(db_category)


@api.delete(
    "/course-sub-category/{category_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个课程子类别",
    response_model=SuccessResponse,
    tags=[Tag.course_sub_categories]
)
async def delete_course_sub_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseSubCategory, category_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course sub category not found."
    )
    if db_category is None:
        raise not_found_exception
    session.delete(db_category)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-sub-category/{category_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="禁用单个课程子类别",
    response_model=SuccessResponse,
    tags=[Tag.course_sub_categories]
)
async def disable_course_sub_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseSubCategory, category_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course sub category not found."
    )
    if db_category is None:
        raise not_found_exception
    if db_category.disabled:
        raise not_found_exception
    db_category.disabled = True
    session.add(db_category)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-sub-category/{category_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="取消禁用单个课程子类别",
    response_model=SuccessResponse,
    tags=[Tag.course_sub_categories]
)
async def activate_course_sub_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_category = session.get(CourseSubCategory, category_id)
    if db_category is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course sub category not found."
        )
    if not db_category.disabled:
        return SuccessResponse(success=True)
    same_name_college = session.exec(
        select(CourseSubCategory)
        .where(CourseSubCategory.disabled == False)
        .where(CourseSubCategory.name == db_category.name)
    ).first()
    if same_name_college is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Exists an active sub category which has the same name."
        )
    db_category.disabled = False
    session.add(db_category)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/course-sub-category/{category_id}/courses", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND,
    ),
    summary="获取单个课程子类别的所有课程",
    response_model=CourseReadList, 
    tags=[Tag.course_sub_categories]
)
async def read_course_sub_category_courses(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course sub category not found."
    )
    main_category = session.get(CourseMainCategory, category_id)
    if main_category is None:
        raise exception
    if main_category.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Course.id))
        .where(col(Course.sub_category_id) == category_id)
    ).one()
    courses = session.exec(
        select(Course)
        .where(col(Course.sub_category_id) == category_id)
        .offset(offset).limit(limit)
    ).all()
    course_read_list = [CourseRead.read(course) for course in courses]
    return CourseReadList(total_count=count, course_read_list=course_read_list)


@api.get(
    "/course-sub-category/{category_id}/main-category",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程子类别对应的主类别",
    response_model=CourseMainCategoryRead,
    tags=[Tag.course_sub_categories]
)   
async def read_course_sub_category_main_category(
    category_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseMainCategoryRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course sub category not found."
    )
    db_category = session.get(CourseSubCategory, category_id)
    if db_category is None:
        raise exception
    if db_category.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseMainCategoryRead.read(db_category.main_category)


@api.post(
    "/courses", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="创建一个课程",
    response_model=CourseRead, 
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.courses]
)
async def create_course(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_course: CourseCreate
) -> CourseRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    same_name_active_course = session.exec(
        select(Course)
        .where(Course.name == new_course.name)
        .where(Course.disabled == False)
    ).first()
    if same_name_active_course is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Existed an active course which has the same name."
        )

    existed_sub_category = session.get(CourseSubCategory, new_course.sub_category_id)
    if existed_sub_category is None or existed_sub_category.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid sub category id."
        )
    if new_course.college_id is not None:
        existed_college = session.get(College, new_course.college_id)
        if existed_college is None or existed_college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Invalid college id."
            )
    db_course = Course.create(new_course)
    session.add(db_course)
    session.commit()
    session.refresh(db_course)
    return CourseRead.read(db_course)


@api.get(
    "/courses", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取所有课程列表",
    response_model=CourseReadList, 
    tags=[Tag.courses]
)
async def read_courses(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CourseReadList:
    count_query = select(func.count(Course.id))
    course_list_query = select(Course)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(Course.disabled == False)
        course_list_query = course_list_query.where(Course.disabled == False)
    count = session.exec(count_query).one()
    db_courses = session.exec(course_list_query.offset(offset).limit(limit)).all()
    course_read_list = [CourseRead.read(course) for course in db_courses]
    return CourseReadList(total_count=count, course_read_list=course_read_list)


@api.get(
    "/courses/{course_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程信息",
    response_model=CourseRead, 
    tags=[Tag.courses]
)
async def read_course(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseRead:
    db_course = session.get(Course, course_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    if db_course is None:
        raise exception
    if db_course.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseRead.read(db_course)


@api.patch(
    "/courses/{course_id}",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="修改单个课程信息",
    response_model=CourseRead, 
    tags=[Tag.courses]
)
async def update_course(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    course_update: CourseUpdate
) -> CourseRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_course = session.get(Course, course_id)
    if db_course is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course sub category not found."
        )
    if course_update.name is not None:
        same_name_active_category = session.exec(
            select(Course)
            .where(Course.name == course_update.name)
            .where(col(Course.id) != course_id)
            .where(Course.disabled == False)
        ).first()
        if same_name_active_category is not None:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_409_CONFLICT,
                detail="Existed a different active course main category which has the same."
            )
    if course_update.sub_category_id is not None:
        sub_category = session.get(CourseSubCategory, course_update.sub_category_id)
        if sub_category is None or sub_category.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Corresponding sub category doesn't exist."
            )
    if course_update.college_id is not None:
        college = session.get(College, course_update.college_id)
        if college is None or college.disabled:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Corresponding college doesn't exist."
            )
    category_changes = course_update.dict(exclude_unset=True)
    for key, value in category_changes.items():
        setattr(db_course, key, value)
    session.add(db_course)
    session.commit()
    session.refresh(db_course)
    return CourseRead.read(db_course)


@api.delete(
    "/courses/{course_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个课程信息",
    response_model=SuccessResponse,
    tags=[Tag.courses]
)
async def delete_course(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_course: Optional[Course] = session.get(Course, course_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    if db_course is None:
        raise not_found_exception
    session.delete(db_course)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/courses/{course_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="禁用单个课程",
    response_model=SuccessResponse,
    tags=[Tag.courses]
)
async def disable_course(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_course: Optional[Course] = session.get(Course, course_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    if db_course is None:
        raise not_found_exception
    if db_course.disabled:
        raise not_found_exception
    db_course.disabled = True
    session.add(db_course)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/courses/{course_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="取消禁用单个课程",
    response_model=SuccessResponse,
    tags=[Tag.courses]
)
async def activate_course(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_course = session.get(Course, course_id)
    if db_course is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course not found."
        )
    if not db_course.disabled:
        return SuccessResponse(success=True)
    same_name_course = session.exec(
        select(Course)
        .where(Course.disabled == False)
        .where(Course.name == db_course.name)
    ).first()
    if same_name_course is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Exists an active course which has the same name."
        )
    db_course.disabled = False
    session.add(db_course)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/courses/{course_id}/main-category",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程对应的主课程类型",
    response_model=CourseMainCategoryRead,
    tags=[Tag.courses]
)   
async def read_course_course_main_category(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseMainCategoryRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    db_course = session.get(Course, course_id)
    if db_course is None:
        raise exception
    if db_course.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseMainCategoryRead.read(db_course.sub_category.main_category)


@api.get(
    "/courses/{course_id}/sub-category",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程对应的子课程类型",
    response_model=CourseSubCategoryRead,
    tags=[Tag.courses]
)   
async def read_course_course_sub_category(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseSubCategoryRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    db_course = session.get(Course, course_id)
    if db_course is None:
        raise exception
    if db_course.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseSubCategoryRead.read(db_course.sub_category)


@api.get(
    "/courses/{course_id}/college",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程对应的学院信息",
    response_model=CollegeRead,
    tags=[Tag.courses]
)   
async def read_course_college(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CollegeRead:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    db_course = session.get(Course, course_id)
    if db_course is None:
        raise exception
    if db_course.disabled and current_user.group is not Group.admin:
        raise exception
    if db_course.college is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course's college not found."
        )
    return CollegeRead.read(db_course.college)


@api.get(
    "/courses/{course_id}/teachers",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程对应的教师",
    response_model=TeacherReadList,
    tags=[Tag.courses]
)
async def read_course_teachers(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> TeacherReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    course = session.get(Course, course_id)
    if course is None:
        raise exception
    if course.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(Teacher.id))
        .join(CourseTeacherLink)
        .where(col(CourseTeacherLink.course_id) == course_id)
        .where(CourseTeacherLink.disabled == False)
    ).one()
    teachers = session.exec(
        select(Teacher)
        .join(CourseTeacherLink)
        .where(col(CourseTeacherLink.course_id) == course_id)
        .where(CourseTeacherLink.disabled == False)
        .offset(offset).limit(limit)
    ).all()
    teacher_read_list = [TeacherRead.read(teacher) for teacher in teachers]
    return TeacherReadList(total_count=count, teacher_read_list=teacher_read_list)


@api.get(
    "/courses/{course_id}/course-teacher-links",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程对应的所有课程教师关联",
    response_model=CourseTeacherLinkReadList, 
    tags=[Tag.courses]
)
async def read_course_course_teacher_links(
    course_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseTeacherLinkReadList:
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course not found."
    )
    course = session.get(Course, course_id)
    if course is None:
        raise exception
    if course.disabled and current_user.group is not Group.admin:
        raise exception
    count = session.exec(
        select(func.count(CourseTeacherLink.id))
        .where(col(CourseTeacherLink.course_id) == course_id)
        .where(CourseTeacherLink.disabled == False)
    ).one()
    links = session.exec(
        select(CourseTeacherLink)
        .where(col(CourseTeacherLink.course_id) == course_id)
        .where(CourseTeacherLink.disabled == False)
        .offset(offset).limit(limit)
    ).all()
    link_list = [CourseTeacherLinkRead.read(link) for link in links]
    return CourseTeacherLinkReadList(total_count=count, link_read_list=link_list)


@api.get(
    "/search/courses", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN
    ),
    summary="搜索课程",
    response_model=CourseReadList, 
    tags=[Tag.courses]
)
def search_courses(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    name: Annotated[Optional[str], Query(min_length=1, max_length=50)] = None,
    college_id: Optional[int] = None,
    course_main_category_id: Optional[int] = None,
    course_sub_category_id: Optional[int] = None,
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CourseReadList:
    count_query = select(func.count(Course.id)).join(CourseSubCategory)
    course_list_query = select(Course).join(CourseSubCategory)
    if name is not None:
        count_query = count_query.where(col(Course.name).contains(name))
        course_list_query = course_list_query.where(col(Course.name).contains(name))
    if college_id is not None:
        count_query = count_query.where(Course.college_id == college_id)
        course_list_query = course_list_query.where(Course.college_id == college_id)
    if course_main_category_id is not None:
        count_query = count_query.where(CourseSubCategory.main_category_id == course_main_category_id)
        course_list_query = course_list_query.where(CourseSubCategory.main_category_id == course_main_category_id)
    if course_sub_category_id is not None:
        count_query = count_query.where(Course.sub_category_id == course_sub_category_id)
        course_list_query = course_list_query.where(Course.sub_category_id == course_sub_category_id)
    if only_active:
        count_query = count_query.where(Course.disabled == False)
        course_list_query = course_list_query.where(Course.disabled == False)
    count = session.exec(count_query).one()
    courses = session.exec(course_list_query.offset(offset).limit(limit)).all()
    course_read_list = [CourseRead.read(course) for course in courses]
    return CourseReadList(total_count=count, course_read_list=course_read_list)


@api.post(
    "/course-teacher-link", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="创建一个课程教师关联",
    response_model=CourseTeacherLinkRead, 
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.course_teacher_links]
)
async def create_course_teacher_link(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_link: CourseTeacherLinkCreate
) -> CourseTeacherLinkRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    existed_course = session.get(Course, new_link.course_id)
    if existed_course is None or existed_course.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid main course id."
        )
    existed_teacher = session.get(Teacher, new_link.teacher_id)
    if existed_teacher is None or existed_teacher.user.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid sub teacher id."
        )
    existed_active_link = session.exec(
        select(CourseTeacherLink)
        .where(CourseTeacherLink.course_id == new_link.course_id)
        .where(CourseTeacherLink.teacher_id == new_link.teacher_id)
        .where(CourseTeacherLink.year == new_link.year)
        .where(CourseTeacherLink.disabled == False)
    ).first()
    if existed_active_link is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Exists an active link which has the same parameters."
        )
    db_link = CourseTeacherLink.create(new_link)
    session.add(db_link)
    session.commit()
    session.refresh(db_link)
    return CourseTeacherLinkRead.read(db_link)


@api.get(
    "/course-teacher-link", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取所有的课程教师关联",
    response_model=CourseTeacherLinkReadList, 
    tags=[Tag.course_teacher_links]
)
async def read_course_teacher_links(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50,
    only_active: Annotated[bool, Query(alias="only-active", description="过滤已被禁用的对象")] = True
) -> CourseTeacherLinkReadList:
    count_query = select(func.count(CourseTeacherLink.id))
    link_list_query = select(CourseTeacherLink)
    if only_active or current_user.group is not Group.admin:
        count_query = count_query.where(CourseTeacherLink.disabled == False)
        link_list_query = link_list_query.where(CourseTeacherLink.disabled == False)
    count = session.exec(count_query).one()
    links = session.exec(link_list_query.offset(offset).limit(limit)).all()
    link_read_list = [CourseTeacherLinkRead.read(link) for link in links]
    return CourseTeacherLinkReadList(total_count=count, link_read_list=link_read_list)


@api.get(
    "/course-teacher-link/{link_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程教师关联信息",
    response_model=CourseTeacherLinkDetailRead,
    tags=[Tag.course_teacher_links]
)
async def read_course_teacher_link(
    link_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseTeacherLinkDetailRead:
    db_link = session.get(CourseTeacherLink, link_id)
    exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course-Teacher-Link not found."
    )
    if db_link is None:
        raise exception
    if db_link.disabled and current_user.group is not Group.admin:
        raise exception
    return CourseTeacherLinkDetailRead.read(db_link)


@api.patch(
    "/course-teacher-link/{link_id}",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_409_CONFLICT
    ),
    summary="修改单个课程教师关联信息",
    response_model=CourseTeacherLinkRead, 
    tags=[Tag.course_teacher_links]
)
async def update_course_teacher_link(
    link_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    link_update: CourseTeacherLinkUpdate
) -> CourseTeacherLinkRead:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_link = session.get(CourseTeacherLink, link_id)
    if db_link is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course teacher link not found."
        )
    existed_course = session.get(Course, link_update.course_id)
    if existed_course is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Corresponding course doesn't exist."
        )
    existed_teacher = session.get(Teacher, link_update.teacher_id)
    if existed_teacher is None or existed_teacher.user.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Corresponding teacher doesn't exist."
        )
    if link_update.enroll_limit < db_link.enroll_count:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Can't shrink enrollment size limit because current enrollment count is larger than the value to be updated."
        )
    existed_link = session.exec(
        select(CourseTeacherLink)
        .where(CourseTeacherLink.disabled == False)
        .where(CourseTeacherLink.id != link_id)
        .where(CourseTeacherLink.course_id == link_update.course_id)
        .where(CourseTeacherLink.teacher_id == link_update.teacher_id)
    ).first()
    if existed_link is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Exists a different link with the same info."
        )
    category_changes = link_update.dict(exclude_unset=True)
    for key, value in category_changes.items():
        setattr(db_link, key, value)
    session.add(db_link)
    session.commit()
    session.refresh(db_link)
    return CourseTeacherLinkRead.read(db_link)


@api.delete(
    "/course-teacher-link/{link_id}",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个课程教师关联信息",
    response_model=SuccessResponse,
    tags=[Tag.course_teacher_links]
)
async def delete_course_teacher_link(
    link_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_link = session.get(CourseTeacherLink, link_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="CourseTeacherLink not found."
    )
    if db_link is None:
        raise not_found_exception
    session.delete(db_link)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-teacher-link/{link_id}/disable",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="禁用单个课程教师关联信息",
    response_model=SuccessResponse,
    tags=[Tag.course_teacher_links]
)
async def disable_course_teacher_link(
    link_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_link = session.get(CourseTeacherLink, link_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="CourseTeacherLink not found."
    )
    if db_link is None:
        raise not_found_exception
    db_link.disabled = True
    session.add(db_link)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-teacher-link/{link_id}/activate",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="取消禁用单个课程教师关联信息",
    response_model=SuccessResponse,
    tags=[Tag.course_teacher_links]
)
async def activate_course_teacher_link(
    link_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    db_link = session.get(CourseTeacherLink, link_id)
    if db_link is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Teacher not found."
        )
    if not db_link.disabled:
        return SuccessResponse(success=True)
    db_link.disabled = False
    session.add(db_link)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/course-teacher-link/{link_id}/enrollments", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程教师关联的选课名单",
    response_model=CourseEnrollmentReadList, 
    tags=[Tag.course_teacher_links]
)
async def read_course_teacher_link_enrollments(
    link_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseEnrollmentReadList:
    permission_denied_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied."
    )
    if current_user.group is Group.student:
        raise permission_denied_exception
    not_found_link_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course teacher link not found."
    )
    link = session.get(CourseTeacherLink, link_id)
    if link is None:
        raise not_found_link_exception
    if link.disabled and current_user.group is not Group.admin:
        raise not_found_link_exception
    if current_user.group is Group.teacher and current_user.id != link.teacher_id:
        raise permission_denied_exception
    count = session.exec(
        select(func.count(CourseEnrollment.id))
        .where(col(CourseEnrollment.course_teacher_link_id) == link_id)
    ).one()
    enrollments = session.exec(
        select(CourseEnrollment)
        .where(col(CourseEnrollment.course_teacher_link_id) == link_id)
        .offset(offset).limit(limit)
    ).all()
    enrollment_read_list = [CourseEnrollmentRead.read(enrollment) for enrollment in enrollments]
    return CourseEnrollmentReadList(total_count=count, enrollment_read_list=enrollment_read_list)


@api.get(
    "/course-teacher-link/{link_id}/schedules", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程教师关联对应的课程安排",
    response_model=CourseScheduleReadList, 
    tags=[Tag.course_teacher_links]
)
async def read_course_teacher_link_schedules(
    link_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50
) -> CourseScheduleReadList:
    not_found_link_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course teacher link not found."
    )
    link = session.get(CourseTeacherLink, link_id)
    if link is None:
        raise not_found_link_exception
    if link.disabled and current_user.group is not Group.admin:
        raise not_found_link_exception
    count = session.exec(
        select(func.count(CourseSchedule.id))
        .where(col(CourseSchedule.course_teacher_link_id) == link_id)
    ).one()
    schedules = session.exec(
        select(CourseSchedule)
        .where(col(CourseSchedule.course_teacher_link_id) == link_id)
        .offset(offset).limit(limit)
    ).all()
    schedule_read_list = [CourseScheduleRead.read(schedule) for schedule in schedules]
    return CourseScheduleReadList(total_count=count, schedule_read_list=schedule_read_list)


@api.post(
    "/course-enrollments", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_409_CONFLICT,
        HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    summary="学生选课",
    response_model=CourseEnrollmentRead, 
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.course_enrollments]
)
async def create_course_enrollment(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_enrollment: CourseEnrollmentCreate,
    admin_override: bool = False
) -> CourseEnrollmentRead:
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to create an enrollment."
    )
    if current_user.group is Group.student:
        if current_user.id != new_enrollment.student_id:
            raise permission_exception
    elif current_user.group is not Group.admin:
        raise permission_exception
    course_teacher_link = session.get(CourseTeacherLink, new_enrollment.course_teacher_link_id)
    if course_teacher_link is None or course_teacher_link.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Course info is broken."
        )
    course_main_category = course_teacher_link.course.sub_category.main_category
    if course_main_category.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Course info is broken."
        )
    time_exception = HTTPException(
        status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
        detail="Not during course enrollment time."
    )
    if course_teacher_link.enroll_count >= course_teacher_link.enroll_limit:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Course capacity is full."
        )
    if not course_main_category.allow_enrollment:
        if current_user.group is not Group.admin:
            raise time_exception
        elif current_user.group is Group.admin and not admin_override:
            raise time_exception
    student = session.get(Student, new_enrollment.student_id)
    if student is None or student.user.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid student id."
        )
    existed_enrollment = session.exec(
        select(CourseEnrollment)
        .where(CourseEnrollment.student_id == new_enrollment.student_id)
        .where(CourseEnrollment.course_teacher_link_id == new_enrollment.course_teacher_link_id)
    ).first()
    if existed_enrollment is not None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_409_CONFLICT,
            detail="Already enrolled."
        )
    db_enrollment = CourseEnrollment.create(new_enrollment)
    session.add(db_enrollment)
    session.commit()
    session.refresh(db_enrollment)
    return CourseEnrollmentRead.read(db_enrollment)


@api.get(
    "/course-enrollments", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN
    ),
    summary="获取所有的学生选课名单",
    response_model=CourseEnrollmentReadList, 
    tags=[Tag.course_enrollments]
)
async def read_course_enrollments(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50
) -> CourseEnrollmentReadList:
    if current_user.group is not Group.admin:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_403_FORBIDDEN,
            detail="Permission denied. You're not an administrator."
        )
    count_query = select(func.count(CourseEnrollment.id))
    list_query = select(CourseEnrollment)
    count = session.exec(count_query).one()
    enrollments = session.exec(list_query.offset(offset).limit(limit)).all()
    enrollment_read_list = [CourseEnrollmentRead.read(enrollment) for enrollment in enrollments]
    return CourseEnrollmentReadList(total_count=count, enrollment_read_list=enrollment_read_list)


@api.get(
    "/course-enrollments/{enrollment_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个学生选课信息",
    response_model=CourseEnrollmentRead,
    tags=[Tag.course_enrollments]
)
async def read_course_enrollment(
    enrollment_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseEnrollment:
    db_enrollment = session.get(CourseEnrollment, enrollment_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course enrollment not found."
    )
    if db_enrollment is None:
        raise not_found_exception
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to view this record."
    )
    if current_user.group is Group.student and current_user.id != db_enrollment.student_id:
        raise permission_exception
    elif (current_user.group is Group.teacher 
          and current_user.id != db_enrollment.course_teacher_link.teacher_id):
        raise permission_exception
    return db_enrollment


@api.delete(
    "/course-enrollments/{enrollment_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    summary="学生退课",
    response_model=SuccessResponse, 
    tags=[Tag.course_enrollments]
)
async def drop_course_enrollment(
    enrollment_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    admin_override: bool = False
) -> SuccessResponse:
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to delete this record."
    )
    enrollment = session.get(CourseEnrollment, enrollment_id)
    if enrollment is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Enrollment record not found."
        )
    if current_user.group is Group.student and enrollment.student_id != current_user.id:
        raise permission_exception
    elif current_user.group is Group.teacher:
        raise permission_exception
    course_main_category = enrollment.course_teacher_link.course.sub_category.main_category
    if course_main_category.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Course info is broken."
        )
    time_exception = HTTPException(
        status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
        detail="Not during course dropping time."
    )
    if not course_main_category.allow_drop:
        if current_user.group is Group.admin and not admin_override:
            raise time_exception
        elif current_user.group is not Group.admin:
            raise time_exception
    session.delete(enrollment)
    session.commit()
    return SuccessResponse(success=True)


@api.patch(
    "/course-enrollments/{enrollment_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND,
        HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR
    ),
    summary="老师登分",
    response_model=SuccessResponse, 
    tags=[Tag.course_enrollments]
)
async def set_course_enrollment_grade(
    enrollment_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    enrollment_update: CourseEnrollmentUpdate,
    admin_override: bool = False
) -> SuccessResponse:
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to modify this record."
    )
    enrollment = session.get(CourseEnrollment, enrollment_id)
    if enrollment is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Enrollment record not found."
        )
    teacher_id = enrollment.course_teacher_link.teacher_id
    if current_user.group is Group.student:
        raise permission_exception
    elif current_user.group is Group.teacher and current_user.id != teacher_id:
        raise permission_exception
    course_main_category = enrollment.course_teacher_link.course.sub_category.main_category
    if course_main_category.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Course info is broken."
        )
    time_exception = HTTPException(
        status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
        detail="Not during course setting grade time."
    )
    if not course_main_category.allow_set_grade:
        if current_user.group is Group.admin and not admin_override:
            raise time_exception
        elif current_user.group is not Group.admin:
            raise time_exception
    enrollment.grade = enrollment_update.grade
    session.add(enrollment)
    session.commit()
    return SuccessResponse(success=True)


@api.post(
    "/course-schedules", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN
    ),
    response_model=CourseScheduleRead, 
    summary="创建课程安排",
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.course_schedules]
)
async def create_course_schedule(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_schedule: CourseScheduleCreate
) -> CourseScheduleRead:
    course_teacher_link = session.get(CourseTeacherLink, new_schedule.course_teacher_link_id)
    if course_teacher_link is None or course_teacher_link.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid course teacher link id."
        )
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to create this record."
    )
    if current_user.group is Group.student:
        raise permission_exception
    elif current_user.group is Group.teacher and current_user.id != course_teacher_link.teacher_id:
        raise permission_exception
    existed_schedules = session.exec(
        select(CourseSchedule)
        .where(CourseSchedule.course_teacher_link_id == new_schedule.course_teacher_link_id)
        .where(CourseSchedule.weekday == new_schedule.weekday)
    ).all()
    available_time: set[int] = {i for i in range(1, 14 + 1)}
    for existed_schedule in existed_schedules:
        for i in range(
            existed_schedule.course_start_time, 
            existed_schedule.course_start_time + existed_schedule.time_duration
        ):
            available_time.remove(i)
    for i in range(
        new_schedule.course_start_time, 
        new_schedule.course_start_time + new_schedule.time_duration
    ):
        if i not in available_time:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Time already being ocupied."
            )
    db_schedule = CourseSchedule.create(new_schedule)
    session.add(db_schedule)
    session.commit()
    session.refresh(db_schedule)
    return CourseScheduleRead.read(db_schedule)


@api.get(
    "/course-schedules", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取所有的课程安排",
    response_model=CourseScheduleReadList, 
    tags=[Tag.course_schedules]
)
async def read_course_schedules(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50
) -> CourseScheduleReadList:
    count_query = select(func.count(CourseSchedule.id))
    list_query = select(CourseSchedule)
    count = session.exec(count_query).one()
    schedules = session.exec(list_query.offset(offset).limit(limit)).all()
    schedule_read_list = [CourseScheduleRead.read(schedule) for schedule in schedules]
    return CourseScheduleReadList(total_count=count, schedule_read_list=schedule_read_list)


@api.get(
    "/course-schedules/{schedule_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个课程安排信息",
    response_model=CourseScheduleRead, 
    tags=[Tag.course_schedules]
)
async def read_course_schedule(
    schedule_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> CourseScheduleRead:
    db_schedule = session.get(CourseSchedule, schedule_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Course schedule not found."
    )
    if db_schedule is None:
        raise not_found_exception
    return CourseScheduleRead.read(db_schedule)


@api.put(
    "/course-schedules/{schedule_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="修改课程安排",
    response_model=CourseScheduleRead, 
    tags=[Tag.course_schedules]
)
async def modify_course_schedule(
    schedule_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    modified_schedule: CourseScheduleModify
) -> CourseScheduleRead:
    db_schedule = session.get(CourseSchedule, schedule_id)
    if db_schedule is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course schedule not found."
        )
    course_teacher_link = db_schedule.course_teacher_link
    if course_teacher_link is None or course_teacher_link.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid course teacher link id."
        )
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to modify this record."
    )
    if current_user.group is Group.student:
        raise permission_exception
    elif current_user.group is Group.teacher and current_user.id != course_teacher_link.teacher_id:
        raise permission_exception
    existed_schedules = session.exec(
        select(CourseSchedule)
        .where(CourseSchedule.course_teacher_link_id == modified_schedule.course_teacher_link_id)
        .where(CourseSchedule.weekday == modified_schedule.weekday)
        .where(CourseSchedule.id != schedule_id)
    ).all()
    available_time: set[int] = {i for i in range(1, 14 + 1)}
    for existed_schedule in existed_schedules:
        for i in range(
            existed_schedule.course_start_time, 
            existed_schedule.course_start_time + existed_schedule.time_duration
        ):
            available_time.remove(i)
    for i in range(
        modified_schedule.course_start_time, 
        modified_schedule.course_start_time + modified_schedule.time_duration
    ):
        if i not in available_time:
            raise HTTPException(
                status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail="Time already being ocupied."
            )
    schedule_changes = modified_schedule.dict(exclude_unset=True)
    for key, value in schedule_changes.items():
        setattr(db_schedule, key, value)
    session.add(db_schedule)
    session.commit()
    session.refresh(db_schedule)
    return CourseScheduleRead.read(db_schedule)


@api.delete(
    "/course-schedules/{schedule_id}",
    responses=responses_of(
        HTTPStatus.HTTP_400_BAD_REQUEST,
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个课程安排",
    response_model=SuccessResponse,
    tags=[Tag.course_schedules]
)
async def delete_course_schedule(
    schedule_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    db_schedule = session.get(CourseSchedule, schedule_id)
    if db_schedule is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Course schedule not found."
        )
    course_teacher_link = db_schedule.course_teacher_link
    if course_teacher_link is None or course_teacher_link.disabled:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_400_BAD_REQUEST,
            detail="Invalid course teacher link id."
        )
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to delete this record."
    )
    if current_user.group is Group.student:
        raise permission_exception
    elif current_user.group is Group.teacher and current_user.id != course_teacher_link.teacher_id:
        raise permission_exception
    session.delete(db_schedule)
    session.commit()
    return SuccessResponse(success=True)


@api.post(
    "/posts", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    response_model=PostRead, 
    summary="创建帖子",
    status_code=HTTPStatus.HTTP_201_CREATED,
    tags=[Tag.posts]
)
async def create_post(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_post: PostCreate
) -> PostRead:
    db_post = Post(title=new_post.title, content=new_post.content, user_id=current_user.id)
    session.add(db_post)
    session.commit()
    session.refresh(db_post)
    return PostRead.read(db_post)


@api.get(
    "/posts", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取所有的帖子",
    response_model=PostReadList, 
    tags=[Tag.posts]
)
async def read_posts(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50
) -> PostReadList:
    count_query = select(func.count(Post.id))
    list_query = select(Post)
    count = session.exec(count_query).one()
    posts = session.exec(list_query.offset(offset).limit(limit)).all()
    post_read_list = [PostRead.read(post) for post in posts]
    return PostReadList(total_count=count, post_read_list=post_read_list)


@api.get(
    "/posts/{post_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单个帖子",
    response_model=PostRead, 
    tags=[Tag.posts]
)
async def read_post(
    post_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> PostRead:
    db_post = session.get(Post, post_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Post not found."
    )
    if db_post is None:
        raise not_found_exception
    return PostRead.read(db_post)


@api.delete(
    "/posts/{post_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单个帖子",
    response_model=SuccessResponse,
    tags=[Tag.posts]
)
async def delete_post(
    post_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
)-> SuccessResponse:
    db_post = session.get(Post, post_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Post not found."
    )
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to delete this post."
    )
    if db_post is None:
        raise not_found_exception
    if current_user.group is not Group.admin:
        if current_user.id != db_post.user_id:
            raise permission_exception
    session.delete(db_post)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/search/posts", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="搜索帖子",
    response_model=PostReadList, 
    tags=[Tag.posts]
)
async def search_posts(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    user_name: Optional[str] = None,
    offset: Annotated[int, Query(ge=0, description="列表查询的偏移量")] = 0,
    limit: Annotated[int, Query(ge=1, le=50, description="列表查询的数量限制")] = 50,
    title: Optional[str] = None
) -> PostReadList:
    count_query = select(func.count(Post.id)).join(User)
    post_list_query = select(Post).join(User)
    if user_name is not None:
        count_query = count_query.where(col(User.name).contains(user_name))
        post_list_query = post_list_query.where(col(User.name).contains(user_name))
    if title is not None:
        count_query = count_query.where(col(Post.title).contains(title))
        post_list_query = post_list_query.where(col(Post.title).contains(title))
    count = session.exec(count_query.offset(offset).limit(limit)).one()
    posts = session.exec(post_list_query.offset(offset).limit(limit)).all()
    post_read_list = [PostRead.read(post) for post in posts]
    return PostReadList(total_count=count, post_read_list=post_read_list)
    
    
@api.get(
    "/posts/{post_id}/replies",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取所有帖子的回复",
    response_model=ReplyReadList,
    tags=[Tag.posts]
)
async def read_post_replies(
    post_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50
) -> ReplyReadList:
    db_post = session.get(Post, post_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Post not found."
    )
    if db_post is None:
        raise not_found_exception
    count = session.exec(
        select(func.count(Reply.id))
        .where(Reply.post_id == post_id)
    ).one()
    replies = session.exec(
        select(Reply)
        .where(Reply.post_id == post_id)
        .offset(offset).limit(limit)
    ).all()
    reply_read_list = [ReplyRead.read(reply) for reply in replies]
    return ReplyReadList(total_count=count, reply_read_list=reply_read_list)


@api.post(
    "/replies",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="创建回复",
    response_model=ReplyRead,
    tags=[Tag.replies]
)
async def create_reply(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    new_reply: ReplyCreate
) -> ReplyRead:
    db_post = session.get(Post, new_reply.post_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Post not found."
    )
    if db_post is None:
        raise not_found_exception
    db_reply = Reply(
        user_id=current_user.id,
        content=new_reply.content,
        post_id=new_reply.post_id,
        ref_reply_id=new_reply.ref_reply_id
    )
    session.add(db_reply)
    session.commit()
    session.refresh(db_reply)
    return ReplyRead.read(db_reply)


@api.get(
    "/replies", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED
    ),
    summary="获取所有的帖子回复",
    response_model=ReplyReadList, 
    tags=[Tag.replies]
)
async def read_replies(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 50
) -> ReplyReadList:
    count_query = select(func.count(Reply.id))
    list_query = select(Reply)
    count = session.exec(count_query).one()
    replies = session.exec(list_query.offset(offset).limit(limit)).all()
    reply_read_list = [ReplyRead.read(reply) for reply in replies]
    return ReplyReadList(total_count=count, reply_read_list=reply_read_list)


@api.get(
    "/replies/{reply_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单条回复",
    response_model=ReplyRead, 
    tags=[Tag.replies]
)
async def read_reply(
    reply_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> ReplyRead:
    db_reply = session.get(Reply, reply_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Post not found."
    )
    if db_reply is None:
        raise not_found_exception
    return ReplyRead.read(db_reply)


@api.delete(
    "/replies/{reply_id}", 
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_403_FORBIDDEN,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="删除单条回复",
    response_model=SuccessResponse,
    tags=[Tag.replies]
)
async def delete_reply(
    reply_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> SuccessResponse:
    db_reply = session.get(Reply, reply_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Reply not found."
    )
    permission_exception = HTTPException(
        status_code=HTTPStatus.HTTP_403_FORBIDDEN,
        detail="Permission denied. You're not allowed to delete this reply."
    )
    if db_reply is None:
        raise not_found_exception
    if current_user.group is not Group.admin and current_user.id != db_reply.user_id:
        raise permission_exception
    related_replies = session.exec(
        select(Reply)
        .where(col(Reply.ref_reply_id) == reply_id)
    ).all()
    session.delete(db_reply)
    for related_reply in related_replies:
        session.delete(related_reply)
    session.commit()
    return SuccessResponse(success=True)


@api.get(
    "/replies/{reply_id}/post",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单条回复对应的帖子",
    response_model=PostRead,
    tags=[Tag.replies]
)
async def read_reply_post(
    reply_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> PostRead:
    db_reply = session.get(Reply, reply_id)
    not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Reply not found."
    )
    if db_reply is None:
        raise not_found_exception
    return PostRead.read(db_reply.post)


@api.get(
    "/replies/{reply_id}/reply",
    responses=responses_of(
        HTTPStatus.HTTP_401_UNAUTHORIZED,
        HTTPStatus.HTTP_404_NOT_FOUND
    ),
    summary="获取单条回复对应的回复（回复另一个回复的回复）",
    response_model=ReplyRead,
    tags=[Tag.replies]
)
async def read_reply_reference_reply(
    reply_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Annotated[Session, Depends(get_database_session)]
) -> ReplyRead:
    db_reply = session.get(Reply, reply_id)
    if db_reply is None:
        raise HTTPException(
            status_code=HTTPStatus.HTTP_404_NOT_FOUND,
            detail="Reply not found."
        )
    ref_reply_not_found_exception = HTTPException(
        status_code=HTTPStatus.HTTP_404_NOT_FOUND,
        detail="Reference reply not found."
    )
    if db_reply.ref_reply_id is None:
        raise ref_reply_not_found_exception
    ref_reply = session.get(Reply, db_reply.ref_reply_id)
    if ref_reply is None:
        raise ref_reply_not_found_exception
    return ReplyRead.read(ref_reply)
