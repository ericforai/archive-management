#!/bin/bash

# 电子会计档案管理系统 - Railway部署脚本

echo "🚀 开始部署电子会计档案管理系统到Railway..."

# 检查Git是否安装
if ! command -v git &> /dev/null; then
    echo "❌ Git未安装，请先安装Git"
    exit 1
fi

# 初始化Git仓库
echo "📦 初始化Git仓库..."
git init
git add .
git commit -m "电子会计档案管理系统 - 准备部署到Railway

- 修复JavaScript语法错误
- 优化Railway部署配置
- 支持SQLite数据库
- 完整的功能特性"

# 获取用户输入的GitHub仓库地址
echo ""
echo "📋 请输入你的GitHub仓库地址："
echo "   格式：https://github.com/你的用户名/仓库名.git"
echo "   如果还没有创建，请先在GitHub上创建空白仓库"
read -p "GitHub仓库地址: " repo_url

if [ -z "$repo_url" ]; then
    echo "❌ 未输入仓库地址"
    exit 1
fi

# 添加远程仓库
echo "🔗 添加远程仓库..."
git remote add origin "$repo_url"
git branch -M main

echo ""
echo "✅ Git初始化完成！"
echo ""
echo "📤 上传到GitHub..."
if git push -u origin main; then
    echo "🎉 成功上传到GitHub！"
    echo ""
    echo "🌐 现在请访问 https://railway.app 进行部署："
    echo ""
    echo "1. 用GitHub账号登录Railway"
    echo "2. 点击 'New Project'"
    echo "3. 选择 'Deploy from GitHub repo'"
    echo "4. 选择你刚上传的仓库"
    echo "5. 等待部署完成（约2-3分钟）"
    echo "6. 获取你的应用URL"
    echo ""
    echo "💡 部署完成后，你的应用将在 https://your-app.railway.app 访问"
    echo ""
    echo "🔧 部署后可能需要的设置："
    echo "   - 在Railway项目中设置环境变量 PORT=5001"
    echo "   - 如果需要数据库，会自动配置PostgreSQL"
    echo ""
else
    echo "❌ 上传失败，请检查："
    echo "   1. 仓库地址是否正确"
    echo "   2. 是否有GitHub访问权限"
    echo "   3. 网络连接是否正常"
fi

echo ""
echo "🎯 部署完成后，你可以："
echo "   - 在浏览器中访问应用"
echo "   - 使用默认管理员账号登录 (admin/admin123)"
echo "   - 开始管理电子会计档案"
echo ""