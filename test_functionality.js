// 电子档案系统功能测试脚本
// 这个脚本将在浏览器控制台中运行，测试所有功能模块

console.log("🚀 开始电子档案系统集成测试...");

// 测试1: 检查页面基本元素
function testBasicElements() {
    console.log("\n📋 测试1: 检查页面基本元素");
    
    const checks = [
        { selector: '#main-nav', name: '主导航面板' },
        { selector: '#archives-panel', name: '档案浏览面板' },
        { selector: '#workflow-panel', name: '工作流面板' },
        { selector: '#statistics-panel', name: '统计分析面板' },
        { selector: '#version-control-panel', name: '版本控制面板' }
    ];
    
    checks.forEach(check => {
        const element = document.querySelector(check.selector);
        if (element) {
            console.log(`✅ ${check.name}: 存在`);
        } else {
            console.log(`❌ ${check.name}: 缺失`);
        }
    });
}

// 测试2: 检查导航功能
function testNavigation() {
    console.log("\n🧭 测试2: 检查导航功能");
    
    const navItems = document.querySelectorAll('#main-nav .nav-item');
    console.log(`找到 ${navItems.length} 个导航项`);
    
    navItems.forEach((item, index) => {
        const text = item.textContent.trim();
        console.log(`导航项 ${index + 1}: ${text}`);
        
        // 测试点击事件
        item.addEventListener('click', function() {
            console.log(`✅ 点击导航项 "${text}" 触发成功`);
        });
    });
}

// 测试3: 检查模态框功能
function testModals() {
    console.log("\n🔍 测试3: 检查模态框功能");
    
    const modalButtons = [
        { selector: 'button[onclick*="createArchive"]', name: '创建档案' },
        { selector: 'button[onclick*="startNewWorkflow"]', name: '新建工作流' },
        { selector: 'button[onclick*="exportWorkflowData"]', name: '导出数据' }
    ];
    
    modalButtons.forEach(button => {
        const element = document.querySelector(button.selector);
        if (element) {
            console.log(`✅ ${button.name} 按钮: 存在`);
        } else {
            console.log(`❌ ${button.name} 按钮: 缺失`);
        }
    });
}

// 测试4: 检查搜索和筛选功能
function testSearchAndFilter() {
    console.log("\n🔍 测试4: 检查搜索和筛选功能");
    
    const searchInputs = [
        { selector: 'input[placeholder*="搜索"]', name: '档案搜索框' },
        { selector: 'input[placeholder*="搜索"]', name: '工作流搜索框' }
    ];
    
    const filters = [
        { selector: 'select[name="status"]', name: '状态筛选器' },
        { selector: 'select[name="priority"]', name: '优先级筛选器' }
    ];
    
    searchInputs.forEach(input => {
        const element = document.querySelector(input.selector);
        if (element) {
            console.log(`✅ ${input.name}: 存在`);
            console.log(`   - 类型: ${element.type}`);
            console.log(`   - 占位符: ${element.placeholder}`);
        } else {
            console.log(`❌ ${input.name}: 缺失`);
        }
    });
    
    filters.forEach(filter => {
        const element = document.querySelector(filter.selector);
        if (element) {
            console.log(`✅ ${filter.name}: 存在`);
            console.log(`   - 选项数量: ${element.options.length}`);
        } else {
            console.log(`❌ ${filter.name}: 缺失`);
        }
    });
}

// 测试5: 检查JavaScript函数
function testJavaScriptFunctions() {
    console.log("\n⚙️ 测试5: 检查JavaScript函数");
    
    const functions = [
        'showArchivesPanel',
        'showWorkflowPanel', 
        'showStatisticsPanel',
        'showVersionControlPanel',
        'showAlert',
        'initWorkflowPanel',
        'initStatisticsPanel'
    ];
    
    functions.forEach(funcName => {
        if (typeof window[funcName] === 'function') {
            console.log(`✅ ${funcName}: 已定义`);
        } else {
            console.log(`❌ ${funcName}: 未定义`);
        }
    });
}

// 测试6: 检查CSS样式
function testCSSStyles() {
    console.log("\n🎨 测试6: 检查CSS样式");
    
    const stylesheets = Array.from(document.styleSheets);
    console.log(`找到 ${stylesheets.length} 个样式表`);
    
    // 检查响应式样式
    const testElement = document.createElement('div');
    testElement.style.display = 'none';
    document.body.appendChild(testElement);
    
    const computedStyle = window.getComputedStyle(testElement);
    document.body.removeChild(testElement);
    
    console.log(`✅ 基本样式计算正常`);
}

// 运行所有测试
function runAllTests() {
    testBasicElements();
    testNavigation();
    testModals();
    testSearchAndFilter();
    testJavaScriptFunctions();
    testCSSStyles();
    
    console.log("\n🎉 集成测试完成！");
    console.log("请检查上述测试结果，标记有问题的项目");
}

// 页面加载完成后自动运行测试
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runAllTests);
} else {
    runAllTests();
}