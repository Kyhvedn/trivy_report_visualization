#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trivy镜像扫描报告处理器 v2.0
用于处理trivy镜像扫描的原始文本报告，生成结构化的HTML报告
支持标准文本格式和JSON格式的trivy报告
"""

import json
import re
import os
import sys
from datetime import datetime
from pathlib import Path

class TrivyImageReportProcessor:
    def __init__(self):
        self.vulnerabilities = []
        self.stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0,
            'total': 0
        }
        self.scan_info = {
            'target': '',
            'type': '',
            'total_vulnerabilities': 0,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    def parse_report(self, file_path):
        """智能解析trivy报告，支持文本和JSON格式"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"报告文件不存在: {file_path}")
            
        try:
            # 首先尝试作为JSON解析
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            # 检查是否是JSON格式
            if content.startswith('{') or content.startswith('['):
                return self._parse_json_report(content)
            else:
                # 作为文本格式解析
                return self._parse_text_report(content)
                
        except json.JSONDecodeError:
            # JSON解析失败，按文本格式处理
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return self._parse_text_report(content)
        except Exception as e:
            raise Exception(f"解析报告时出错: {e}")
    
    def _parse_json_report(self, content):
        """解析JSON格式的trivy报告"""
        try:
            data = json.loads(content)
            
            # 处理不同结构的JSON
            if isinstance(data, dict):
                if 'Results' in data:
                    return self._parse_json_v2(data)
                else:
                    return self._parse_json_v1(data)
            elif isinstance(data, list):
                for item in data:
                    self._parse_json_v1(item)
                    
        except Exception as e:
            print(f"JSON解析失败: {e}")
            return False
    
    def _parse_json_v1(self, data):
        """解析trivy JSON格式v1"""
        try:
            # 提取扫描目标信息
            if 'ArtifactName' in data:
                self.scan_info['target'] = data['ArtifactName']
            if 'ArtifactType' in data:
                self.scan_info['type'] = data['ArtifactType']
                
            # 提取漏洞信息
            results = data.get('Results', [])
            for result in results:
                vulnerabilities = result.get('Vulnerabilities', [])
                for vuln in vulnerabilities:
                    self._extract_vulnerability(vuln)
                    
            return True
        except Exception as e:
            print(f"解析JSON v1格式失败: {e}")
            return False
    
    def _parse_json_v2(self, data):
        """解析trivy JSON格式v2"""
        try:
            results = data.get('Results', [])
            for result in results:
                target = result.get('Target', '')
                if target:
                    self.scan_info['target'] = target
                    
                vulnerabilities = result.get('Vulnerabilities', [])
                for vuln in vulnerabilities:
                    self._extract_vulnerability(vuln)
                    
            return True
        except Exception as e:
            print(f"解析JSON v2格式失败: {e}")
            return False
    
    def _extract_vulnerability(self, vuln):
        """从漏洞数据中提取标准化信息"""
        try:
            severity = vuln.get('Severity', 'UNKNOWN').upper()
            
            vulnerability = {
                'id': vuln.get('VulnerabilityID', 'N/A'),
                'package': vuln.get('PkgName', 'N/A'),
                'version': vuln.get('InstalledVersion', 'N/A'),
                'fixedVersion': vuln.get('FixedVersion', 'N/A'),
                'severity': severity,
                'description': vuln.get('Description', '无描述信息'),
                'status': vuln.get('Status', 'N/A'),
                'title': vuln.get('Title', ''),
                'references': vuln.get('References', [])
            }
            
            self.vulnerabilities.append(vulnerability)
            self._update_stats(severity)
            
        except Exception as e:
            print(f"提取漏洞信息失败: {e}")
    
    def _parse_text_report(self, content):
        """解析文本格式的trivy报告"""
        try:
            lines = content.split('\n')
            current_target = None
            parsing_vulns = False
            
            for line in lines:
                line = line.strip()
                
                # 提取目标信息
                if line.startswith('Report Summary'):
                    continue
                elif '┌─' in line and 'Target' in line:
                    continue
                elif '│' in line and 'debian' in line:
                    # 解析目标行
                    match = re.search(r'│\s*(.+?)\s+│\s*(\w+)\s+│\s*(\d+)\s+│', line)
                    if match:
                        self.scan_info['target'] = match.group(1).strip()
                        self.scan_info['type'] = match.group(2).strip()
                        self.scan_info['total_vulnerabilities'] = int(match.group(3))
                
                # 提取漏洞统计
                elif 'Total:' in line and 'UNKNOWN:' in line:
                    # 解析统计行
                    stats_match = re.search(r'Total:\s*(\d+)\s*\((UNKNOWN:\s*(\d+),\s*LOW:\s*(\d+),\s*MEDIUM:\s*(\d+),\s*HIGH:\s*(\d+),\s*CRITICAL:\s*(\d+))\)', line)
                    if stats_match:
                        self.stats['total'] = int(stats_match.group(1))
                        self.stats['unknown'] = int(stats_match.group(3))
                        self.stats['low'] = int(stats_match.group(4))
                        self.stats['medium'] = int(stats_match.group(5))
                        self.stats['high'] = int(stats_match.group(6))
                        self.stats['critical'] = int(stats_match.group(7))
                        parsing_vulns = True
                        continue
                
                # 解析漏洞详情表格
                if parsing_vulns and line.startswith('│') and not line.startswith('├') and not line.startswith('└'):
                    # 跳过表头
                    if 'Library' in line or 'Vulnerability' in line:
                        continue
                        
                    # 解析漏洞行
                    vuln_data = self._parse_vulnerability_line(line)
                    if vuln_data:
                        self.vulnerabilities.append(vuln_data)
                        
            return True
            
        except Exception as e:
            print(f"解析文本报告失败: {e}")
            return False
    
    def _parse_vulnerability_line(self, line):
        """解析单行漏洞信息"""
        try:
            # 使用正则表达式解析表格格式
            parts = line.strip('│').split('│')
            if len(parts) >= 7:
                library = parts[0].strip()
                vulnerability = parts[1].strip()
                severity = parts[2].strip().upper()
                status = parts[3].strip()
                installed = parts[4].strip()
                fixed = parts[5].strip()
                title = parts[6].strip()
                
                # 清理数据
                if vulnerability == '-' or not vulnerability:
                    return None
                    
                return {
                    'id': vulnerability,
                    'package': library,
                    'version': installed,
                    'fixedVersion': fixed if fixed and fixed != '-' else 'N/A',
                    'severity': severity,
                    'description': title,
                    'status': status,
                    'title': title,
                    'references': []
                }
                
        except Exception as e:
            print(f"解析漏洞行失败: {e}")
            
        return None
    
    def _update_stats(self, severity):
        """更新统计信息"""
        severity_lower = severity.lower()
        if severity_lower in self.stats:
            self.stats[severity_lower] += 1
        self.stats['total'] += 1
    
    def generate_html_report(self, output_path):
        """生成HTML报告"""
        html_template = self._get_html_template()
        
        # 准备数据
        vulnerabilities_json = json.dumps(self.vulnerabilities, ensure_ascii=False, indent=2)
        stats_json = json.dumps(self.stats, ensure_ascii=False)
        
        # 替换模板变量
        html_content = html_template.format(
            report_date=datetime.now().strftime('%Y-%m-%d'),
            scan_target=self.scan_info.get('target', '未知镜像'),
            scan_type=self.scan_info.get('type', '未知类型'),
            scan_date=self.scan_info.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            critical_count=self.stats['critical'],
            high_count=self.stats['high'],
            medium_count=self.stats['medium'],
            low_count=self.stats['low'],
            unknown_count=self.stats['unknown'],
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
    <title>Trivy 镜像安全扫描报告</title>
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
                        Trivy 镜像安全扫描报告
                    </h1>
                    <p class="lead mb-4">基于 Trivy 扫描结果的综合安全分析报告</p>
                    <div class="d-flex align-items-center">
                        <span class="badge bg-light text-dark fs-6 me-3">
                            <i class="fas fa-calendar me-2"></i>
                            {report_date}
                        </span>
                        <span class="badge bg-light text-dark fs-6">
                            <i class="fas fa-folder me-2"></i>
                            {scan_target}
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
            <div class="col-md-2">
                <div class="card metric-card">
                    <div class="metric-number text-danger">{critical_count}</div>
                    <div class="metric-label">严重漏洞</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card metric-card">
                    <div class="metric-number text-warning">{high_count}</div>
                    <div class="metric-label">高危漏洞</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card metric-card">
                    <div class="metric-number text-info">{medium_count}</div>
                    <div class="metric-label">中危漏洞</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card metric-card">
                    <div class="metric-number text-success">{low_count}</div>
                    <div class="metric-label">低危漏洞</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card metric-card">
                    <div class="metric-number text-secondary">{unknown_count}</div>
                    <div class="metric-label">未知级别</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card metric-card">
                    <div class="metric-number text-dark">{total_count}</div>
                    <div class="metric-label">总计</div>
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
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-bs-toggle="pill" data-bs-target="#low-vulns" type="button">
                            低危 <span class="badge bg-success" id="low-tab-count">{low_count}</span>
                        </button>
                    </li>
                </ul>

                <div class="tab-content" id="vulnerabilityContent">
                    <div class="tab-pane fade show active" id="all-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="critical-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="high-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="medium-vulns" role="tabpanel"></div>
                    <div class="tab-pane fade" id="low-vulns" role="tabpanel"></div>
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
                labels: ['严重', '高危', '中危', '低危', '未知'],
                datasets: [{{
                    data: [stats.critical, stats.high, stats.medium, stats.low, stats.unknown],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d'],
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
                            maxRotation: 90,
                            minRotation: 90,
                            font: {{
                                size: 11
                            }}
                        }},
                        grid: {{
                            display: false
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
                                <div class="text-muted small mt-1">
                                    <i class="fas fa-info-circle me-1"></i>
                                    ${{vuln.description || vuln.title}}
                                </div>
                            </div>
                            <div class="col-md-4 text-end">
                                <button class="btn btn-sm btn-outline-primary" 
                                        onclick="showDetails('${{vuln.id}}')">
                                    <i class="fas fa-eye me-1"></i>详情
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }});

            container.innerHTML = html;
        }}

        // 显示漏洞详情
        function showDetails(vulnId) {{
            const vuln = vulnerabilityData.find(v => v.id === vulnId);
            if (!vuln) return;

            const modalContent = document.getElementById('modalContent');
            modalContent.innerHTML = `
                <div class="row">
                    <div class="col-md-12">
                        <h5><strong>${{vuln.id}}</strong></h5>
                        <hr>
                        <p><strong>包名:</strong> ${{vuln.package}}</p>
                        <p><strong>当前版本:</strong> ${{vuln.version}}</p>
                        <p><strong>修复版本:</strong> ${{vuln.fixedVersion}}</p>
                        <p><strong>严重程度:</strong> 
                            <span class="severity-badge severity-${{vuln.severity.toLowerCase()}}">${{vuln.severity}}</span>
                        </p>
                        <p><strong>状态:</strong> ${{vuln.status}}</p>
                        <p><strong>描述:</strong> ${{vuln.description || vuln.title}}</p>
                        ${{vuln.references && vuln.references.length > 0 ? `
                        <p><strong>参考链接:</strong></p>
                        <ul>
                            ${{vuln.references.map(ref => `<li><a href="${{ref}}" target="_blank">${{ref}}</a></li>`).join('')}}
                        </ul>
                        ` : ''}}
                    </div>
                </div>
            `;

            const modal = new bootstrap.Modal(document.getElementById('vulnerabilityModal'));
            modal.show();
        }}

        // 搜索功能
        document.getElementById('searchInput').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            const filteredData = vulnerabilityData.filter(vuln => 
                vuln.id.toLowerCase().includes(searchTerm) ||
                vuln.package.toLowerCase().includes(searchTerm) ||
                vuln.description.toLowerCase().includes(searchTerm)
            );

            renderVulnerabilities(filteredData, 'all-vulns');
            
            // 更新其他标签页的计数
            const severityCounts = {{
                critical: filteredData.filter(v => v.severity.toUpperCase() === 'CRITICAL').length,
                high: filteredData.filter(v => v.severity.toUpperCase() === 'HIGH').length,
                medium: filteredData.filter(v => v.severity.toUpperCase() === 'MEDIUM').length,
                low: filteredData.filter(v => v.severity.toUpperCase() === 'LOW').length
            }};

            Object.keys(severityCounts).forEach(severity => {{
                const container = document.getElementById(`${{severity}}-vulns`);
                const filtered = filteredData.filter(v => v.severity.toUpperCase() === severity.toUpperCase());
                renderVulnerabilities(filtered, `${{severity}}-vulns`);
            }});
        }});

        // 初始化渲染
        document.addEventListener('DOMContentLoaded', function() {{
            renderVulnerabilities(vulnerabilityData, 'all-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity.toUpperCase() === 'CRITICAL'), 'critical-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity.toUpperCase() === 'HIGH'), 'high-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity.toUpperCase() === 'MEDIUM'), 'medium-vulns');
            renderVulnerabilities(vulnerabilityData.filter(v => v.severity.toUpperCase() === 'LOW'), 'low-vulns');
        }});
    </script>
</body>
</html>'''

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Trivy镜像扫描报告处理器')
    parser.add_argument('report_file', help='trivy扫描报告文件路径')
    parser.add_argument('-o', '--output', help='输出HTML文件路径', default='trivy_image_report.html')
    
    args = parser.parse_args()
    
    try:
        processor = TrivyImageReportProcessor()
        
        # 解析报告
        print(f"正在解析报告: {args.report_file}")
        success = processor.parse_report(args.report_file)
        
        if success:
            print(f"解析完成，共发现 {len(processor.vulnerabilities)} 个漏洞")
            
            # 生成HTML报告
            processor.generate_html_report(args.output)
            print(f"报告已生成: {args.output}")
        else:
            print("解析失败")
            
    except Exception as e:
        print(f"处理失败: {e}")

if __name__ == '__main__':
    main()