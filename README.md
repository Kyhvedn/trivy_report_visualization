# Trivy 报告可视化工具

## 版本更新
###v1:
输出结果同时需求txt格式和json格式的原始报告
###v2.1：
智能格式识别 ：自动识别trivy报告的格式（文本或JSON）
统一的输出格式 ：无论输入是文本还是JSON格式，输出都是一致的HTML结构
X轴标签显示优化：将X轴标签改为竖向显示（90度旋转），并优化字体大小和网格线

## 项目简介

这是一个基于 Trivy 容器安全扫描输出的可视化报告生成工具，能够将 Trivy 扫描结果转换为美观、交互式的 HTML 报告。
时不时会更新~

## 功能特性

### 🎯 核心功能
- **自动解析**：支持解析 Trivy JSON 和 TXT 格式报告
- **可视化展示**：使用 Chart.js 生成饼图和柱状图
- **交互式界面**：支持搜索、筛选和详情查看
- **响应式设计**：适配桌面和移动设备
- **中文界面**：完整的中文报告界面

### 📊 数据展示
- **统计卡片**：严重、高危、中危、低危漏洞数量
- **漏洞分布图**：饼图展示各严重程度分布
- **包风险统计**：柱状图展示各包的风险数量
- **详细列表**：完整的漏洞详情表格
- **模态框详情**：点击可查看完整漏洞信息

### 🔍 交互功能
- **实时搜索**：支持 CVE ID 和包名搜索
- **标签筛选**：按严重程度筛选漏洞
- **详情弹窗**：点击漏洞查看完整信息
- **外部链接**：直接访问官方 CVE 页面

## 文件说明

### 主要文件
- `trivy_report_visualization-v1.py` - 报告生成器主程序
- `trivy_security_report-example.html` - 报告模板
- Trivy TXT 格式报告（需求）
- Trivy JSON 格式报告（需求）

### 使用方法

#### 1. 基本使用
```bash
python trivy_report_visualization-v1.py
```

#### 2. 自定义输出路径
```bash
python trivy_report_visualization-v1.py 自定义报告名称.html
```

#### 3. 修改输入文件
在 `trivy_report_visualization-v1.py` 中修改文件路径：
```python
txt_path = "path/to/your/scan_result.txt"
json_path = "path/to/your/result.json"
```

## 技术栈

### 前端技术
- **Bootstrap 5.3** - 响应式 UI 框架
- **Chart.js** - 图表可视化
- **Font Awesome** - 图标库
- **原生 JavaScript** - 交互功能

### 后端技术
- **Python 3** - 数据处理
- **标准库** - JSON 解析、文件操作
- **Jinja2 模板** - HTML 生成

## 报告结构

### 页面布局
1. **英雄区域** - 报告标题和基本信息
2. **统计卡片** - 漏洞数量概览
3. **图表区域** - 漏洞分布和包风险统计
4. **漏洞详情** - 可筛选的漏洞列表
5. **详情弹窗** - 点击漏洞查看完整信息

### 数据字段
- CVE ID
- 包名和版本
- 修复版本
- 严重程度
- CVSS 评分
- 漏洞描述
- CWE 分类
- 发布时间
- 参考链接

## 使用示例

### 场景 1：日常安全扫描
1. 使用 Trivy 扫描容器：`trivy fs /path/to/jar > scan_result.txt`
2. 使用 Trivy 生成 JSON：`trivy fs --format json /path/to/jar > result.json`
3. 运行报告生成器：`python trivy_report_visualization-v1.py`
4. 打开生成的 HTML 报告查看结果

### 场景 2：安全审计报告
1. 收集多个扫描结果
2. 统一使用本工具生成报告
3. 导出为 PDF 供管理层查看
4. 分享给开发团队进行修复

## 扩展功能

### 自定义样式
可以通过修改 CSS 变量来自定义主题颜色：
```css
:root {
    --critical-color: #dc3545;
    --high-color: #fd7e14;
    --medium-color: #ffc107;
    --low-color: #28a745;
}
```

### 添加新图表
在 HTML 模板中添加新的图表容器和 JavaScript 配置即可扩展可视化功能。

### 集成 CI/CD
可以将此工具集成到 CI/CD 流程中：
```yaml
# GitHub Actions 示例
- name: Generate Security Report
  run: |
    trivy fs --format json /app > result.json
    python generate_report.py security_report.html
```

## 注意事项

1. **文件编码**：确保 JSON 文件使用 UTF-8 编码
2. **文件大小**：对于大型扫描结果，可能需要优化性能
3. **浏览器兼容性**：支持现代浏览器（Chrome、Firefox、Safari、Edge）
4. **安全考虑**：报告可能包含敏感信息，注意访问控制

## 故障排除

### 常见问题

**Q: 报告显示 0 个漏洞**
A: 检查 JSON 文件格式是否正确，确认 Trivy 扫描命令是否包含漏洞信息

**Q: 图表不显示**
A: 确保网络连接正常，CDN 资源可访问

**Q: 中文显示乱码**
A: 确认 HTML 文件编码为 UTF-8

### 调试信息
运行脚本时添加调试输出：
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 许可证

本项目采用 MIT 许可证，可自由使用和修改。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进此工具。

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交 GitHub Issue
- 发送邮件至项目维护者

---

**最后更新：** 2025-08-20
