# Educational Management System

#### 介绍
教务选课系统后端

#### 软件架构
使用 FastAPI 和 SQLModel 搭建后端

#### 软件依赖
1. python 3.11 及以上版本
1. MySQL 8.0 及以上版本
1. navicat 数据库管理软件
1. 最好是较新的 Linux 环境

#### 安装教程
1. 安装 python 3.11 和 MySQL 8.0 及以上版本
1. 创建虚拟环境 `python -m venv venv`
1. 激活虚拟环境（假设为 Linux）：`source venv/bin/activate`
1. 安装 mysqlclient 依赖：`sudo apt-get install python3-dev default-libmysqlclient-dev build-essential pkg-config`
1. 安装 Python 的依赖的包：`pip install -r requirements.txt`
1. 用 Navicat 数据库管理软件为 MySQL 建立用户，用户名 edusystemuser，密码 F827mwBF.B3Ek2_y
1. 用 Navicat 建一个数据库名为 edusystem
1. 用 Navicat 数据库软件向 edusystemuser 用户提供 edusystem 数据库的全部权限
1. 用 Navicat 向数据库导入 edusystem.sql 中表的定义。
1. 使用 uvicorn 运行后端 `uvicorn backend.api:api`

#### 使用说明

##### 本地部署版：

1. 在运行 uvicorn 后访问 http://127.0.0.1:8000/docs/ 可查看后端的 API，并测试。
2. setup_admin 中包含初始化的管理员信息。
3. API 文档页右上角的 Authentication 可以登录初始化的管理员账号密码，测试所有 API。
