# 电子会计档案管理系统

基于DA/T 94-2022标准开发的电子会计档案管理系统

## 功能特性

- 📁 档案管理：支持各类会计档案的数字化管理
- 🔍 智能检索：基于内容相似度的智能档案检索
- 📊 数据统计：可视化数据统计和分析
- 🔐 权限管理：多角色权限控制
- 📋 审计跟踪：完整的操作日志记录

## 技术栈

- 后端：Flask + SQLAlchemy + PostgreSQL
- 前端：HTML5 + CSS3 + JavaScript + Bootstrap
- 部署：支持Docker、Gunicorn

## 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 运行应用
python app.py
```

访问 http://localhost:5001

## 快速部署

### Railway部署（推荐）

1. 将项目上传到GitHub
2. 访问 https://railway.app
3. 连接GitHub仓库
4. Railway自动检测并部署

### Render部署

1. 访问 https://render.com
2. 选择 "Web Services"
3. 连接GitHub仓库
4. 设置环境变量：`PORT=5001`

## 环境要求

- Python 3.8+
- PostgreSQL 12+ (生产环境)
- Redis (可选，用于缓存)

## 许可证

MIT License