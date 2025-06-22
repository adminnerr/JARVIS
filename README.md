# Java-
分析pom.xml

📖 简介
JARVIS是一款基于Python的Java项目安全分析工具，通过解析pom.xml文件自动检测：

项目架构（Spring Boot/MVC/JSP等）

JSP解析环境

已知漏洞依赖

安全配置风险

✨ 核心功能
功能模块	检测内容
架构识别	Spring Boot/Spring MVC/JSP+Servlet
JSP环境分析	Tomcat/Jetty JSP引擎、JSTL标签库等  Tomcat/Jetty JSP 引擎、
漏洞扫描	Log4j/Shiro/Fastjson等组件的CVE漏洞
Log4j/Shiro/Fastjson 等组件的 CVE 漏洞
安全建议	文件上传RCE风险、未授权访问等
🛠️ 快速开始
环境要求
Python 3.6+  Python 3.6+ 版

Tkinter（通常内置）

使用步骤
bash  重击
# 1. 下载工具
```
git clone https://github.com/yourrepo/JARVIS.git
cd JARVIS
```

# 2. 运行分析工具
```python jarvis.py```

# 3. 在GUI界面粘贴pom.xml内容后点击"Analyze"
📊 输出示例
```
=== 项目类型分析 ===
✅ 检测到Spring Boot项目

=== JSP环境检测 ===
使用JSP: 是

=== 漏洞警告 ===
‼️ fastjson:1.2.58 - 存在RCE漏洞(CVE-2020-35490)
```


⚠误报：工具只是起到辅助作用，不要过于相信工具,会存在有的Java项目在pom.xml导入了druid相关依赖但是在实际项目中并没有使用druid的情况
