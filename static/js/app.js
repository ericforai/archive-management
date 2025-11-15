// 电子会计档案管理系统 - 主要JavaScript文件

// 全局配置
const CONFIG = {
    API_BASE_URL: 'http://localhost:5001/api/v1',
    TOKEN_KEY: 'auth_token',
    USER_KEY: 'current_user',
    REFRESH_INTERVAL: 30000 // 30秒刷新一次数据
};

// 全局变量
let currentUser = null;
let authToken = null;
let refreshTimer = null;

// 工具函数
const utils = {
    // 显示警告消息
    showAlert(message, type = 'info') {
        const alertDiv = document.getElementById('login-alert');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;
        alertDiv.classList.remove('d-none');
        
        setTimeout(() => {
            alertDiv.classList.add('d-none');
        }, 5000);
    },

    // API请求封装
    async apiRequest(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE_URL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        // 添加认证令牌
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || '请求失败');
            }

            return data;
        } catch (error) {
            console.error('API请求错误:', error);
            throw error;
        }
    },

    // 保存用户信息到本地存储
    saveUserData(token, userData) {
        localStorage.setItem(CONFIG.TOKEN_KEY, token);
        localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(userData));
        authToken = token;
        currentUser = userData;
    },

    // 从本地存储获取用户信息
    loadUserData() {
        const token = localStorage.getItem(CONFIG.TOKEN_KEY);
        const userData = localStorage.getItem(CONFIG.USER_KEY);
        
        if (token && userData) {
            authToken = token;
            currentUser = JSON.parse(userData);
            return true;
        }
        return false;
    },

    // 清除用户数据
    clearUserData() {
        localStorage.removeItem(CONFIG.TOKEN_KEY);
        localStorage.removeItem(CONFIG.USER_KEY);
        authToken = null;
        currentUser = null;
    },

    // 格式化日期
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString('zh-CN');
    },

    // 格式化文件大小
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

// 认证相关功能
const auth = {
    // 用户登录
    async login(username, password, rememberMe = false) {
        try {
            utils.showAlert('正在登录...', 'info');
            
            const response = await utils.apiRequest('/security/login', {
                method: 'POST',
                body: JSON.stringify({
                    username,
                    password,
                    remember_me: rememberMe
                })
            });

            if (response.success && response.data === '登录成功') {
                const userData = response.message;
                utils.saveUserData(userData.access_token, {
                    username: userData.user.username,
                    role: userData.user.roles[0] || 'user',
                    permissions: userData.user.permissions,
                    full_name: userData.user.full_name,
                    email: userData.user.email,
                    department: userData.user.department,
                    id: userData.user.id,
                    session_id: userData.session_id,
                    expires_in: userData.expires_in
                });

                utils.showAlert('登录成功！正在跳转...', 'success');
                
                setTimeout(() => {
                    this.showMainApp();
                }, 1000);
                
                return true;
            } else {
                throw new Error(response.message || '登录失败');
            }
        } catch (error) {
            utils.showAlert(`登录失败: ${error.message}`, 'danger');
            return false;
        }
    },

    // 显示主应用界面
    showMainApp() {
        document.getElementById('login-page').classList.add('d-none');
        document.getElementById('main-app').classList.remove('d-none');
        
        // 更新用户信息
        if (currentUser) {
            document.getElementById('current-user').textContent = currentUser.username;
        }
        
        // 加载默认页面
        this.showPage('dashboard');
        
        // 启动自动刷新
        this.startAutoRefresh();
    },

    // 显示登录页面
    showLoginPage() {
        document.getElementById('login-page').classList.remove('d-none');
        document.getElementById('main-app').classList.add('d-none');
        
        // 停止自动刷新
        this.stopAutoRefresh();
        utils.clearUserData();
    },

    // 页面切换
    showPage(pageName) {
        // 隐藏所有页面
        document.querySelectorAll('.page').forEach(page => {
            page.classList.add('d-none');
        });
        
        // 显示目标页面
        const targetPage = document.getElementById(`${pageName}-page`);
        if (targetPage) {
            targetPage.classList.remove('d-none');
        }
        
        // 更新导航状态
        document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[onclick="showPage('${pageName}')"]`).classList.add('active');
        
        // 根据页面类型加载数据
        switch (pageName) {
            case 'dashboard':
                dashboard.loadData();
                break;
            case 'archives':
                archives.loadData();
                break;
            case 'users':
                users.loadData();
                break;
            case 'audit':
                audit.loadData();
                break;
        }
    },

    // 用户登出
    async logout() {
        try {
            await utils.apiRequest('/security/logout', {
                method: 'POST'
            });
        } catch (error) {
            console.error('登出请求失败:', error);
        } finally {
            this.showLoginPage();
        }
    },

    // 自动刷新
    startAutoRefresh() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
        }
        
        refreshTimer = setInterval(() => {
            if (currentUser && authToken) {
                dashboard.loadStatistics();
            }
        }, CONFIG.REFRESH_INTERVAL);
    },

    // 停止自动刷新
    stopAutoRefresh() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    }
};

// 仪表板功能
const dashboard = {
    // 加载仪表板数据
    async loadData() {
        await this.loadStatistics();
        await this.loadRecentActivities();
    },

    // 加载统计数据
    async loadStatistics() {
        try {
            // 这里应该调用实际的统计API
            // 目前使用模拟数据
            document.getElementById('total-archives').textContent = '1,234';
            document.getElementById('total-users').textContent = '25';
            document.getElementById('today-visits').textContent = '156';
        } catch (error) {
            console.error('加载统计数据失败:', error);
        }
    },

    // 加载近期活动
    async loadRecentActivities() {
        try {
            const response = await utils.apiRequest('/audit/logs');
            
            if (response.success && response.data) {
                this.renderRecentActivities(response.data.slice(0, 10)); // 只显示最新的10条
            } else {
                this.renderRecentActivities([]);
            }
        } catch (error) {
            console.error('加载近期活动失败:', error);
            this.renderRecentActivities([]);
        }
    },

    // 渲染近期活动
    renderRecentActivities(activities) {
        const container = document.getElementById('recent-activities');
        
        if (activities.length === 0) {
            container.innerHTML = '<div class="text-center text-muted"><p>暂无活动记录</p></div>';
            return;
        }

        let html = '<div class="timeline">';
        activities.forEach(activity => {
            html += `
                <div class="timeline-item">
                    <div class="timeline-marker"></div>
                    <div class="timeline-content">
                        <h6 class="timeline-title">${activity.operation_details?.action || '未知操作'}</h6>
                        <p class="timeline-description">${activity.operation_details?.description || ''}</p>
                        <small class="timeline-time">${utils.formatDate(activity.created_at)}</small>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        container.innerHTML = html;
    }
};

// 档案管理功能
const archives = {
    // 加载档案数据
    async loadData() {
        await this.loadArchives();
    },

    // 加载档案列表
    async loadArchives() {
        try {
            const response = await utils.apiRequest('/archive-library');
            
            if (response.success && response.data) {
                this.renderArchives(response.data);
            } else {
                this.renderArchives([]);
            }
        } catch (error) {
            console.error('加载档案失败:', error);
            this.renderArchives([]);
        }
    },

    // 渲染档案列表
    renderArchives(archives) {
        const container = document.getElementById('archives-table');
        
        if (archives.length === 0) {
            container.innerHTML = '<div class="text-center text-muted"><p>暂无档案数据</p></div>';
            return;
        }

        let html = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>档案名称</th>
                            <th>分类</th>
                            <th>上传时间</th>
                            <th>文件大小</th>
                            <th>状态</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        archives.forEach(archive => {
            html += `
                <tr>
                    <td>
                        <div class="d-flex align-items-center">
                            <i class="fas fa-file-alt fa-2x text-primary me-3"></i>
                            <div>
                                <h6 class="mb-0">${archive.title || '未命名档案'}</h6>
                                <small class="text-muted">${archive.description || ''}</small>
                            </div>
                        </div>
                    </td>
                    <td><span class="badge bg-info">${archive.category || '未分类'}</span></td>
                    <td>${utils.formatDate(archive.created_at)}</td>
                    <td>${utils.formatFileSize(archive.file_size || 0)}</td>
                    <td>
                        <span class="badge bg-success">已上传</span>
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" onclick="archives.viewArchive(${archive.id})">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-outline-info" onclick="archives.downloadArchive(${archive.id})">
                                <i class="fas fa-download"></i>
                            </button>
                            <button class="btn btn-outline-danger" onclick="archives.deleteArchive(${archive.id})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = html;
    },

    // 查看档案
    viewArchive(archiveId) {
        // 实现查看档案逻辑
        console.log('查看档案:', archiveId);
        alert(`查看档案 ${archiveId}`);
    },

    // 下载档案
    downloadArchive(archiveId) {
        // 实现下载档案逻辑
        console.log('下载档案:', archiveId);
        alert(`下载档案 ${archiveId}`);
    },

    // 删除档案
    async deleteArchive(archiveId) {
        if (!confirm('确定要删除这个档案吗？')) {
            return;
        }

        try {
            const response = await utils.apiRequest(`/archive-library/${archiveId}`, {
                method: 'DELETE'
            });

            if (response.success) {
                alert('档案删除成功');
                this.loadArchives(); // 重新加载列表
            } else {
                throw new Error(response.message || '删除失败');
            }
        } catch (error) {
            console.error('删除档案失败:', error);
            alert(`删除失败: ${error.message}`);
        }
    }
};

// 用户管理功能
const users = {
    // 加载用户数据
    async loadData() {
        try {
            // 这里应该调用用户管理API
            // 目前使用模拟数据
            this.renderUsers([
                {
                    id: 1,
                    username: 'admin',
                    role: '管理员',
                    email: 'admin@example.com',
                    last_login: '2024-01-15T10:30:00',
                    status: 'active'
                },
                {
                    id: 2,
                    username: 'user1',
                    role: '用户',
                    email: 'user1@example.com',
                    last_login: '2024-01-14T15:20:00',
                    status: 'active'
                }
            ]);
        } catch (error) {
            console.error('加载用户数据失败:', error);
            this.renderUsers([]);
        }
    },

    // 渲染用户列表
    renderUsers(users) {
        const container = document.getElementById('users-table');
        
        if (users.length === 0) {
            container.innerHTML = '<div class="text-center text-muted"><p>暂无用户数据</p></div>';
            return;
        }

        let html = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>用户名</th>
                            <th>角色</th>
                            <th>邮箱</th>
                            <th>最后登录</th>
                            <th>状态</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        users.forEach(user => {
            const statusClass = user.status === 'active' ? 'success' : 'danger';
            const statusText = user.status === 'active' ? '活跃' : '停用';
            
            html += `
                <tr>
                    <td>
                        <div class="d-flex align-items-center">
                            <div class="avatar me-3">${user.username.charAt(0).toUpperCase()}</div>
                            <div>
                                <h6 class="mb-0">${user.username}</h6>
                            </div>
                        </div>
                    </td>
                    <td><span class="badge bg-primary">${user.role}</span></td>
                    <td>${user.email}</td>
                    <td>${utils.formatDate(user.last_login)}</td>
                    <td>
                        <span class="badge bg-${statusClass}">${statusText}</span>
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" onclick="users.editUser(${user.id})">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="btn btn-outline-${statusClass === 'success' ? 'danger' : 'success'}" 
                                    onclick="users.toggleUserStatus(${user.id})">
                                <i class="fas fa-${statusClass === 'success' ? 'ban' : 'check'}"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = html;
    },

    // 编辑用户
    editUser(userId) {
        console.log('编辑用户:', userId);
        alert(`编辑用户 ${userId}`);
    },

    // 切换用户状态
    toggleUserStatus(userId) {
        console.log('切换用户状态:', userId);
        alert(`切换用户 ${userId} 的状态`);
    }
};

// 审计日志功能
const audit = {
    // 加载审计日志
    async loadData() {
        try {
            const response = await utils.apiRequest('/audit/logs');
            
            if (response.success && response.data) {
                this.renderAuditLogs(response.data);
            } else {
                this.renderAuditLogs([]);
            }
        } catch (error) {
            console.error('加载审计日志失败:', error);
            this.renderAuditLogs([]);
        }
    },

    // 渲染审计日志
    renderAuditLogs(logs) {
        const container = document.getElementById('audit-table');
        
        if (logs.length === 0) {
            container.innerHTML = '<div class="text-center text-muted"><p>暂无审计日志</p></div>';
            return;
        }

        let html = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>时间</th>
                            <th>用户</th>
                            <th>操作</th>
                            <th>资源</th>
                            <th>IP地址</th>
                            <th>状态</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        logs.forEach(log => {
            const operation = log.operation_details?.action || '未知操作';
            const description = log.operation_details?.description || '';
            const successClass = log.success ? 'success' : 'danger';
            const successText = log.success ? '成功' : '失败';
            
            html += `
                <tr>
                    <td>
                        <small>${utils.formatDate(log.created_at)}</small>
                    </td>
                    <td>${log.username || '系统'}</td>
                    <td>
                        <div>
                            <strong>${operation}</strong>
                            <br>
                            <small class="text-muted">${description}</small>
                        </div>
                    </td>
                    <td>${log.resource || '-'}</td>
                    <td>
                        <code>${log.ip_address || '-'}</code>
                    </td>
                    <td>
                        <span class="badge bg-${successClass}">${successText}</span>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = html;
    }
};

// 文件上传功能
async function uploadFiles() {
    const fileInput = document.getElementById('file-input');
    const titleInput = document.getElementById('archive-title');
    const descriptionInput = document.getElementById('archive-description');
    const categorySelect = document.getElementById('archive-category');
    
    const files = fileInput.files;
    const title = titleInput.value.trim();
    const description = descriptionInput.value.trim();
    const category = categorySelect.value;

    if (files.length === 0) {
        alert('请选择要上传的文件');
        return;
    }

    if (!title) {
        alert('请输入档案标题');
        return;
    }

    const formData = new FormData();
    for (let file of files) {
        formData.append('files', file);
    }
    formData.append('title', title);
    formData.append('description', description);
    formData.append('category', category);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/archive-library`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            },
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            alert('文件上传成功！');
            
            // 关闭模态框并重置表单
            const modal = bootstrap.Modal.getInstance(document.getElementById('uploadModal'));
            modal.hide();
            document.getElementById('upload-form').reset();
            
            // 重新加载档案列表
            archives.loadArchives();
        } else {
            throw new Error(data.message || '上传失败');
        }
    } catch (error) {
        console.error('上传文件失败:', error);
        alert(`上传失败: ${error.message}`);
    }
}

// 搜索功能
function searchArchives() {
    const searchInput = document.getElementById('archive-search');
    const query = searchInput.value.trim().toLowerCase();
    
    // 实现搜索逻辑
    console.log('搜索档案:', query);
}

// 刷新档案列表
function refreshArchives() {
    archives.loadArchives();
}

// 全局函数，供HTML调用
function showPage(pageName) {
    auth.showPage(pageName);
}

function logout() {
    auth.logout();
}

function showProfile() {
    alert('个人资料功能待实现');
}

// 初始化应用
document.addEventListener('DOMContentLoaded', function() {
    // 检查是否有保存的用户信息
    if (utils.loadUserData()) {
        // 自动登录并显示主应用
        auth.showMainApp();
    }
    
    // 绑定登录表单事件
    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        const rememberMe = document.getElementById('remember-me').checked;
        
        if (!username || !password) {
            utils.showAlert('请输入用户名和密码', 'warning');
            return;
        }
        
        auth.login(username, password, rememberMe);
    });
    
    // 绑定密码显示/隐藏功能
    document.getElementById('toggle-password').addEventListener('click', function() {
        const passwordInput = document.getElementById('password');
        const toggleBtn = this;
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            passwordInput.type = 'password';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
        }
    });
    
    // 绑定搜索功能
    document.getElementById('archive-search').addEventListener('input', searchArchives);
    
    console.log('电子会计档案管理系统前端已初始化');
});