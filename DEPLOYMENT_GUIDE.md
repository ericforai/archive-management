# 🚀 Railway部署指南

## 📋 准备工作

### 1. 创建GitHub仓库
1. 访问 https://github.com
2. 点击右上角的 "+" 号
3. 选择 "New repository"
4. 仓库名：`archive-management` (或你喜欢的名字)
5. 设为 **Public** （免费版Railway需要公开仓库）
6. 不要勾选 "Add a README file"
7. 点击 "Create repository"

### 2. 自动部署
在项目根目录运行部署脚本：

```bash
# 给脚本执行权限
chmod +x deploy_to_railway.sh

# 运行部署脚本
./deploy_to_railway.sh
```

脚本会自动：
- ✅ 初始化Git仓库
- ✅ 添加所有文件
- ✅ 提交代码
- ✅ 推送到GitHub

## 🌐 Railway部署步骤

### 步骤1：登录Railway
1. 访问 https://railway.app
2. 点击 "Login"
3. 选择 "Login with GitHub"
4. 授权Railway访问你的GitHub

### 步骤2：创建新项目
1. 在Railway控制台点击 "New Project"
2. 选择 "Deploy from GitHub repo"
3. 从列表中找到你的仓库
4. 点击 "Deploy Now"

### 步骤3：等待部署
- ⏱️ 部署通常需要2-3分钟
- 📊 你可以在 "Deployments" 标签页查看进度
- 📝 构建日志会显示详细的安装过程

### 步骤4：获取访问URL
部署完成后：
1. 进入项目仪表板
2. 点击你的应用服务
3. 在 "Settings" 标签页找到 "Domains"
4. 会显示形如 `https://archive-management-production.up.railway.app` 的URL

## 🔧 可能需要的配置

### 环境变量设置
如果需要，在Railway项目设置中添加：
- `PORT`: `5001`
- `FLASK_ENV`: `production`
- `SECRET_KEY`: `your-custom-secret-key`

### 数据库配置
Railway会自动：
- 🗄️ 提供PostgreSQL数据库（如需要）
- 🔗 配置 `DATABASE_URL` 环境变量
- 📊 重写SQLite配置为PostgreSQL

## 🧪 部署后测试

### 功能测试清单
- [ ] 应用可以正常访问
- [ ] 登录页面加载正常
- [ ] 默认管理员登录 (admin/admin123)
- [ ] 档案管理功能可用
- [ ] 统计数据展示正常
- [ ] 文件上传功能正常

### 性能检查
- [ ] 页面加载速度 < 3秒
- [ ] 搜索响应时间 < 2秒
- [ ] 移动端访问正常

## 🔍 故障排除

### 常见问题

**1. 部署失败**
```
检查requirements.txt是否存在
检查Python版本兼容性
查看构建日志中的错误信息
```

**2. 应用无法启动**
```
检查Procfile内容是否正确
验证端口配置 (PORT=5001)
查看应用日志中的错误
```

**3. 数据库连接问题**
```
Railway会自动配置PostgreSQL
检查DATABASE_URL环境变量
SQLite在生产环境中可能不稳定
```

**4. 静态文件无法访问**
```
确认static文件夹存在
检查Flask的static_folder配置
验证文件路径大小写
```

## 📞 获取帮助

### 日志查看
在Railway控制台：
1. 选择你的服务
2. 点击 "Deployments" 标签
3. 点击最新的部署
4. 查看构建和运行日志

### 社区支持
- Railway官方文档：https://docs.railway.app
- GitHub仓库提交Issue
- Stack Overflow搜索相关问题

## 🎯 部署成功后的下一步

1. **配置自定义域名**（可选）
   - 在Railway的Settings > Domains中添加
   - 配置DNS记录

2. **设置监控**
   - Railway提供基础的监控信息
   - 可以集成第三方监控工具

3. **定期备份**
   - 虽然Railway有自动备份
   - 建议定期导出重要数据

4. **安全加固**
   - 更改默认管理员密码
   - 配置HTTPS（Railway自动提供）
   - 定期更新依赖包

---

**🎉 恭喜！你的电子会计档案管理系统已成功部署！**

现在可以通过公网URL访问你的应用了。