#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trivy报告生成器
基于Trivy扫描输出生成美观的HTML报告
"""

import json
import re
import os
from datetime import datetime
from pathlib import Path

class TrivyReportGenerator:
    def __init__(self, txt_path, json_path):
        self.txt_path = txt_path
        self.json_path = json_path
        self.vulnerabilities = []
        self.stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }
        
    def parse_json_report(self):
        """解析JSON格式的报告"""
        try:
            with open(self.json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 处理不同格式的JSON结构
            if isinstance(data, list):
                # 如果是数组格式
                for item in data:
                    self._extract_vulnerabilities(item)
            elif isinstance(data, dict):
                # 如果是对象格式
                self._extract_vulnerabilities(data)
                
        except Exception as e:
            print(f"解析JSON报告时出错: {e}")
            
    def _extract_vulnerabilities(self, data):
        """从数据中提取漏洞信息"""
        try:
            # 处理Results数组
            results = data.get('Results', [])
            for result in results:
                # 直接获取Vulnerabilities，而不是从Artifacts获取
                vulns = result.get('Vulnerabilities', [])
                for vuln in vulns:
                    vulnerability = {
                        'id': vuln.get('VulnerabilityID', ''),
                        'package': vuln.get('PkgName', ''),
                        'version': vuln.get('InstalledVersion', ''),
                        'fixedVersion': vuln.get('FixedVersion', ''),
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'description': vuln.get('Description', ''),
                        'cvss': self._get_cvss_score(vuln),
                        'cwe': vuln.get('CweIDs', []),
                        'references': vuln.get('References', []),
                        'published': vuln.get('PublishedDate', '')
                    }
                    self.vulnerabilities.append(vulnerability)
                    self._update_stats(vulnerability['severity'])
                    
        except Exception as e:
            print(f"提取漏洞信息时出错: {e}")
            
    def _get_cvss_score(self, vuln):
        """获取CVSS评分"""
        try:
            cvss_data = vuln.get('CVSS', {})
            if cvss_data:
                # 优先使用nvd的评分
                if 'nvd' in cvss_data:
                    return cvss_data['nvd'].get('V3Score', 0.0)
                elif 'redhat' in cvss_data:
                    return cvss_data['redhat'].get('V3Score', 0.0)
                else:
                    # 使用第一个可用的评分
                    for source, data in cvss_data.items():
                        if 'V3Score' in data:
                            return data['V3Score']
                        elif 'V2Score' in data:
                            return data['V2Score']
            return 0.0
        except:
            return 0.0
            
    def _update_stats(self, severity):
        """更新统计信息"""
        severity_lower = severity.lower()
        if severity_lower in self.stats:
            self.stats[severity_lower] += 1
        self.stats['total'] += 1
        
    def parse_txt_report(self):
        """解析TXT格式的报告"""
        try:
            with open(self.txt_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 提取扫描路径信息
            scan_path_match = re.search(r'Scan path: (.+)', content)
            if scan_path_match:
                self.scan_path = scan_path_match.group(1)
                
            # 提取扫描时间
            scan_time_match = re.search(r'Scan time: (.+)', content)
            if scan_time_match:
                self.scan_time = scan_time_match.group(1)
                
        except Exception as e:
            print(f"解析TXT报告时出错: {e}")
            
    def generate_html_report(self, output_path):
        """生成HTML报告"""
        html_template = self._get_html_template()
        
        # 准备数据
        vulnerabilities_json = json.dumps(self.vulnerabilities, ensure_ascii=False, indent=2)
        stats_json = json.dumps(self.stats, ensure_ascii=False)
        
        # 替换模板变量
        html_content = html_template.format(
            report_date=datetime.now().strftime('%Y-%m-%d'),
            scan_path=getattr(self, 'scan_path', '/opt/t00ls/jar'),
            scan_time=getattr(self, 'scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            critical_count=self.stats['critical'],
            high_count=self.stats['high'],
            medium_count=self.stats['medium'],
            low_count=self.stats['low'],
            total_count=self.stats['total'],
            vulnerabilities_json=vulnerabilities_json,
            stats_json=stats_json
        )
        
        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"HTML报告已生成: {output_path}")
        
    def _get_html_template(self):
        """获取HTML模板"""
        return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trivy 容器安全扫描报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {{
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #28a745;
            --unknown-color: #6c757d;
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --hover-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }}

        body {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
        }}

        .hero-section {{
            background: var(--primary-gradient);
            color: white;
            padding: 60px 0;
            margin-bottom: 40px;
        }}

        .card {{
            border: none;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            margin-bottom: 25px;
        }}

        .card:hover {{
            box-shadow: var(--hover-shadow);
            transform: translateY(-2px);
        }}

        .card-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px 15px 0 0 !important;
            padding: 20px;
        }}

        .severity-badge {{
            font-size: 0.8em;
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: bold;
        }}

        .severity-critical {{ background-color: var(--critical-color); color: white; }}
        .severity-high {{ background-color: var(--high-color); color: white; }}
        .severity-medium {{ background-color: var(--medium-color); color: black; }}
        .severity-low {{ background-color: var(--low-color); color: white; }}
        .severity-unknown {{ background-color: var(--unknown-color); color: white; }}

        .metric-card {{
            text-align: center;
            padding: 30px 20px;
        }}

        .metric-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .metric-label {{
            color: #6c757d;
            font-size: 1.1rem;
        }}

        .vulnerability-item {{
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }}

        .vulnerability-item:hover {{
            background: #e9ecef;
        }}

        .cve-id {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #667eea;
        }}

        .package-name {{
            font-weight: 600;
            color: #495057;
        }}

        .fixed-version {{
            color: #28a745;
            font-weight: bold;
        }}

        .chart-container {{
            position: relative;
            height: 300px;
            margin: 20px 0;
        }}

        .search-box {{
            margin-bottom: 20px;
        }}

        .fade-in {{
            animation: fadeIn 0.5s ease-in;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
</head>
<body>
    <div class="hero-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1 class="display-4 fw-bold mb-3">
                        <i class="fas fa-shield-alt me-3"></i>
                        Trivy 容器安全扫描报告
                    </h1>
                    <p class="lead mb-4">基于 Trivy 扫描结果的综合安全分析报告</p>
                    <div class="d-flex align-items-center">
                        <span class="badge bg-light text-dark fs-6 me-3">
                            <i class="fas fa-calendar me-2"></i>
                            {report_date}
                        </span>
                        <span class="badge bg-light text-dark fs-6">
                            <i class="fas fa-folder me-2"></i>
                            {scan_path}
                        </span>
                    </div>
                </div>
                <div class="col-md-4 text-center">
                    <div class="bg-white bg-opacity-20 rounded-circle p-4 d-inline-block">
                        <i class="fas fa-bug fa-4x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container-fluid px-4">
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-number text-danger">{critical_count}</div>
                    <div class="metric-label">严重漏洞</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-number text-warning">{high_count}</div>
                    <div class="metric-label">高危漏洞</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-number text-info">{medium_count}</div>
                    <div class="metric-label">中危漏洞</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="metric-number text-success">{low_count}</div>
                    <div class="metric-label">低危漏洞</div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>漏洞分布</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>包风险统计</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="packageChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h5 class="mb-0"><i class="fas fa-list me-2"></i>漏洞详情</h5>
                    </div>
                    <div class="col-md-4">
                        <input type="text" class="form-control" id="searchInput" placeholder="搜索 CVE ID 或包名...">
                    </div>
                </div>
            </div>
            <div class="card-body">
                <ul class="nav nav-pills mb-3" id="severityTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" data-bs-toggle="pill" data-bs-target="#all-vulns" type="button">
                            全部 <span class="badge bg-secondary" id="all-count">{total_count}</span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-bs-toggle="pill" data-bs-target="#critical-vulns" type="button">
                            严重 <span class="badge bg-danger" id="critical-tab-count">{critical_count}</span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-bs-toggle="pill" data-bs-target="#high-vulns" type="button">
                            高危 <span class="badge bg-warning text-dark" id="high-tab-count">{high_count}</span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-bs-toggle="pill" data-bs-target="#medium-vulns" type="button">
                            中危 <span class="badge bg-info" id="medium-tab-count">{medium_count}</span>
                        </button>
                    </li>
                </ul>

                <div class="tab-content" id="vulnerabilityContent">
                    <div class="tab-pane fade show active" id="all-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="critical-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="high-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="medium-vulns" role="tabpanel"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="vulnerabilityModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">漏洞详情</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="modalContent"></div>
            </div>
        </div>
    </div>

    <script>
        // 从Python生成的数据
        const vulnerabilityData = {vulnerabilities_json};
        const stats = {stats_json};

        // 创建饼图
        const ctx1 = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx1, {{
            type: 'doughnut',
            data: {{
                labels: ['严重', '高危', '中危', '低危'],
                datasets: [{{
                    data: [stats.critical, stats.high, stats.medium, stats.low],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 20,
                            usePointStyle: true
                        }}
                    }}
                }}
            }}
        }});

        // 创建包风险柱状图
        const packageStats = {{}};
        vulnerabilityData.forEach(v => {{
            if (!packageStats[v.package]) packageStats[v.package] = 0;
            packageStats[v.package]++;
        }});

        const ctx2 = document.getElementById('packageChart').getContext('2d');
        new Chart(ctx2, {{
            type: 'bar',
            data: {{
                labels: Object.keys(packageStats),
                datasets: [{{
                    label: '漏洞数量',
                    data: Object.values(packageStats),
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }},
                    x: {{
                        ticks: {{
                            maxRotation: 45
                        }}
                    }}
                }}
            }}
        }});

        // 渲染漏洞列表
        function renderVulnerabilities(data, containerId) {{
            const container = document.getElementById(containerId);
            if (!container) return;

            let html = '';
            data.forEach(vuln => {{
                const severityClass = `severity-${{vuln.severity.toLowerCase()}}`;
                html += `
                    <div class="vulnerability-item fade-in">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <div class="d-flex align-items-center mb-2">
                                    <span class="severity-badge ${{severityClass}}">${{vuln.severity}}</span>
                                    <span class="cve-id ms-3">${{vuln.id}}</span>
                                </div>
                                <div class="package-name mb-1">${{vuln.package}}</div>
                                <div class="text-muted small">
                                    <i class="fas fa-code-branch me-1"></i>
                                    ${{vuln.version}} → 
                                    <span class="fixed-version">${{vuln.fixedVersion}}</span>
                                </div>
                            </div>
                            <div class="col-md-4 text-end">
                                <button class="btn btn-sm btn-outline-primary" 
                                        onclick="showVulnerabilityDetails('${{vuln.id}}')">
                                    <i class="fas fa-info-circle me-1"></i>详情
                                </button>
                            </div>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted">${{vuln.description}}</small>
                        </div>
                    </div>
                `;
            }});

            container.innerHTML = html;
        }}

        // 显示漏洞详情
        function showVulnerabilityDetails(vulnId) {{
            const vuln = vulnerabilityData.find(v => v.id === vulnId);
            if (!vuln) return;

            const modalContent = document.getElementById('modalContent');
            modalContent.innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <h6>CVE ID</h6>
                        <p class="cve-id">${{vuln.id}}</p>
                        
                        <h6>包名</h6>
                        <p class="package-name">${{vuln.package}}</p>
                        
                        <h6>版本</h6>
                        <p>${{vuln.version}} → <span class="fixed-version">${{vuln.fixedVersion}}</span></p>
                        
                        <h6>严重程度</h6>
                        <span class="severity-badge severity-${{vuln.severity.toLowerCase()}}">${{vuln.severity}}</span>
                    </div>
                    <div class="col-md-6">
                        <h6>CVSS 评分</h6>
                        <p class="text-danger fw-bold">${{vuln.cvss}}/10.0</p>
                        
                        <h6>CWE 分类</h6>
                        <p>${{vuln.cwe.join(', ')}}</p>
                        
                        <h6>发布时间</h6>
                        <p>${{vuln.published}}</p>
                    </div>
                </div>
                <hr>
                <h6>描述</h6>
                <p>${{vuln.description}}</p>
                
                <h6>参考链接</h6>
                <ul class="list-unstyled">
                    ${{vuln.references.map(ref => 
                        `<li><a href="${{ref}}" target="_blank" class="text-decoration-none">
                            <i class="fas fa-external-link-alt me-2"></i>${{ref}}
                        </a></li>`
                    ).join('')}}
                </ul>
            `;

            new bootstrap.Modal(document.getElementById('vulnerabilityModal')).show();
        }}

        // 搜索功能
        document.getElementById('searchInput').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            const filtered = vulnerabilityData.filter(v => 
                v.id.toLowerCase().includes(searchTerm) || 
                v.package.toLowerCase().includes(searchTerm)
            );
            renderVulnerabilities(filtered, 'all-vulns');
        }});

        // 初始化页面
        document.addEventListener('DOMContentLoaded', function() {{
            // 渲染各个标签页的内容
            renderVulnerabilities(vulnerabilityData, 'all-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity === 'CRITICAL'), 'critical-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity === 'HIGH'), 'high-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity === 'MEDIUM'), 'medium-vulns');
        }});
    </script>
</body>
</html>'''

    def run(self, output_path='trivy_report.html'):
        """运行完整的报告生成流程"""
        print("开始解析Trivy报告...")
        
        # 解析报告
        self.parse_json_report()
        self.parse_txt_report()
        
        # 生成HTML报告
        self.generate_html_report(output_path)
        
        # 打印统计信息
        print("\n=== 扫描统计 ===")
        print(f"总漏洞数: {self.stats['total']}")
        print(f"严重漏洞: {self.stats['critical']}")
        print(f"高危漏洞: {self.stats['high']}")
        print(f"中危漏洞: {self.stats['medium']}")
        print(f"低危漏洞: {self.stats['low']}")
        
        return output_path

if __name__ == "__main__":
    # 文件路径
    txt_path = r"c:\Users\xiaoy\Desktop\系统与工具开发\Excel数据处理工具\trivy报告信息处理脚本v1\scan_result.txt"
    json_path = r"c:\Users\xiaoy\Desktop\系统与工具开发\Excel数据处理工具\trivy报告信息处理脚本v1\result.json"
    
    # 生成报告
    generator = TrivyReportGenerator(txt_path, json_path)
    output_file = generator.run('trivy_security_report_real.html')
    
    print(f"\n报告已生成: {output_file}")
    print("请用浏览器打开查看")
