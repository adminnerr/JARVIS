import tkinter as tk
from tkinter import scrolledtext, messagebox
from xml.etree import ElementTree as ET
import re
from datetime import datetime

VULNERABILITY_DB = {
    "fastjson": {
        "1.2.24": {"vulnerable": True, "issues": ["RCE (CVE-2017-18349)"], "severity": "高危"},
        "1.2.25": {"vulnerable": False, "issues": ["已修复RCE漏洞"], "severity": "无"},
        "1.2.28": {"vulnerable": True, "issues": ["RCE (CVE-2017-18349)"], "severity": "高危"},
        "1.2.47": {"vulnerable": True, "issues": ["RCE (CVE-2019-14540)"], "severity": "高危"},
        "1.2.55": {"vulnerable": True, "issues": ["RCE (CVE-2020-35490)"], "severity": "高危"},
        "1.2.68": {"vulnerable": False, "issues": ["已修复多个RCE漏洞"], "severity": "无"},
        "1.2.80": {"vulnerable": True, "issues": ["RCE (CVE-2022-25845)"], "severity": "高危"},
        "default": {"issues": ["建议升级到1.2.83或更高版本"], "severity": "中危"}
    },
    "shiro": {
        "1.2.4": {"vulnerable": True, "issues": ["反序列化漏洞 (CVE-2016-4437)"], "severity": "高危"},
        "1.2.5": {"vulnerable": False, "issues": ["已修复CVE-2016-4437"], "severity": "无"},
        "1.4.1": {"vulnerable": True, "issues": ["身份验证绕过 (CVE-2020-1957)"], "severity": "高危"},
        "1.4.2": {"vulnerable": True, "issues": ["身份验证绕过 (CVE-2020-11989)"], "severity": "高危"},
        "1.5.0": {"vulnerable": True, "issues": ["身份验证绕过 (CVE-2020-13933)"], "severity": "高危"},
        "1.6.0": {"vulnerable": False, "issues": ["已修复多个漏洞"], "severity": "无"},
        "default": {"issues": ["建议升级到1.7.1或更高版本"], "severity": "中危"}
    },
    "log4j": {
        "2.0-beta9": {"vulnerable": True, "issues": ["RCE (CVE-2017-5645)"], "severity": "高危"},
        "2.0": {"vulnerable": False, "issues": ["已修复CVE-2017-5645"], "severity": "无"},
        "2.0-2.14.1": {"vulnerable": True, "issues": ["Log4Shell (CVE-2021-44228)"], "severity": "高危"},
        "2.15.0": {"vulnerable": True, "issues": ["DoS (CVE-2021-45046)"], "severity": "中危"},
        "2.16.0": {"vulnerable": False, "issues": ["已修复Log4Shell漏洞"], "severity": "无"},
        "default": {"issues": ["建议升级到2.17.1或更高版本"], "severity": "中危"}
    },
    "mysql-connector-java": {
        "5.1.0-5.1.48": {"vulnerable": True, "issues": ["多个漏洞 (CVE-2019-2692, CVE-2020-2931等)"],
                         "severity": "中危"},
        "8.0.19": {"vulnerable": True, "issues": ["信息泄露 (CVE-2020-2934)"], "severity": "中危"},
        "8.0.23": {"vulnerable": False, "issues": ["已修复多个漏洞"], "severity": "无"},
        "default": {"issues": ["建议升级到8.0.28或更高版本"], "severity": "中危"}
    },
    "druid": {
        "1.1.10": {"vulnerable": True, "issues": ["未授权访问"], "severity": "高危"},
        "1.1.22": {"vulnerable": True, "issues": ["未授权访问"], "severity": "高危"},
        "1.2.0": {"vulnerable": False, "issues": ["已修复未授权访问"], "severity": "无"},
        "default": {"issues": ["建议升级到1.2.8或更高版本并配置访问控制"], "severity": "中危"}
    },
    "swagger": {
        "2.6.0": {"vulnerable": True, "issues": ["未授权API文档访问"], "severity": "中危"},
        "2.9.2": {"vulnerable": True, "issues": ["未授权API文档访问"], "severity": "中危"},
        "3.0.0": {"vulnerable": False, "issues": ["默认需要认证"], "severity": "无"},
        "default": {"issues": ["建议配置访问控制或升级到3.0.0+"], "severity": "低危"}
    }
}


class PomAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("JARVIS  by kai_kk")
        self.root.geometry("1000x800")
        self.create_widgets()

    def create_widgets(self):
        # 标题
        tk.Label(self.root, text="Java 项目依赖分析工具", font=("Arial", 16)).pack(pady=10)

        # 说明文本
        tk.Label(self.root, text="请将 pom.xml 内容粘贴到下方文本框，然后点击分析按钮").pack()

        # 输入文本框
        self.text_area = scrolledtext.ScrolledText(self.root, width=120, height=25, wrap=tk.WORD)
        self.text_area.pack(pady=10)

        # 分析按钮
        self.analyze_btn = tk.Button(self.root, text="分析 pom.xml", command=self.analyze_pom)
        self.analyze_btn.pack(pady=5)

        # 结果文本框
        self.result_area = scrolledtext.ScrolledText(self.root, width=120, height=25, wrap=tk.WORD)
        self.result_area.pack(pady=10)
        self.result_area.config(state=tk.DISABLED)

        # 清空按钮
        self.clear_btn = tk.Button(self.root, text="清空", command=self.clear_text)
        self.clear_btn.pack(pady=5)

    def clear_text(self):
        self.text_area.delete(1.0, tk.END)
        self.result_area.config(state=tk.NORMAL)
        self.result_area.delete(1.0, tk.END)
        self.result_area.config(state=tk.DISABLED)

    def analyze_pom(self):
        pom_content = self.text_area.get(1.0, tk.END).strip()
        if not pom_content:
            messagebox.showerror("错误", "请输入 pom.xml 内容")
            return

        try:
            # 移除可能的BOM字符
            if pom_content.startswith('\ufeff'):
                pom_content = pom_content[1:]

            root = ET.fromstring(pom_content)

            # 处理命名空间
            ns = {'ns': 'http://maven.apache.org/POM/4.0.0'}

            result = {
                "architecture": None,
                "jsp_environment": {
                    "has_jsp": False,
                    "servlet_container": None,
                    "jsp_version": None,
                    "container_version": None
                },
                "persistence_framework": None,
                "dependencies": {},
                "vulnerabilities": [],
                "security_issues": []
            }

            # 执行各项分析
            self.detect_architecture(root, ns, result)
            self.detect_persistence_framework(root, ns, result)
            self.analyze_dependencies(root, ns, result)
            self.check_vulnerabilities(result)
            self.check_security_issues(root, ns, result)

            # 显示结果
            self.display_results(result)

        except ET.ParseError as e:
            messagebox.showerror("解析错误", f"pom.xml 格式错误: {str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"分析过程中发生错误: {str(e)}")

    def find_artifact(self, root, artifact_id, ns):
        """安全查找依赖项的方法"""
        deps = []
        # 带命名空间查找
        for dep in root.findall(".//ns:dependency", ns):
            artifact = dep.find("ns:artifactId", ns)
            if artifact is not None and artifact_id in artifact.text:
                deps.append(dep)

        # 不带命名空间查找
        if not deps:
            for dep in root.findall(".//dependency"):
                artifact = dep.find("artifactId")
                if artifact is not None and artifact_id in artifact.text:
                    deps.append(dep)
        return deps

    def detect_architecture(self, root, ns, result):
        # 检查是否是Spring Boot项目
        parent_artifact = None
        parent = root.find("ns:parent", ns)
        if parent is not None:
            parent_artifact = parent.find("ns:artifactId", ns)
        if parent_artifact is None:
            parent = root.find("parent")
            if parent is not None:
                parent_artifact = parent.find("artifactId")

        if parent_artifact is not None and "spring-boot-starter-parent" in parent_artifact.text:
            result["architecture"] = "Spring Boot"
            self.detect_embedded_servlet_container(root, ns, result)
            return

        # 检查是否是Spring MVC项目
        spring_mvc_deps = self.find_artifact(root, "spring-webmvc", ns)
        if spring_mvc_deps:
            result["architecture"] = "Spring MVC"
            self.detect_servlet_container(root, ns, result)
            return

        # 检查是否是JSP/Servlet项目
        servlet_deps = self.find_artifact(root, "servlet-api", ns)
        jsp_deps = self.find_artifact(root, "jsp-api", ns)

        if servlet_deps or jsp_deps:
            result["architecture"] = "JSP/Servlet"
            result["jsp_environment"]["has_jsp"] = True
            self.detect_servlet_container(root, ns, result)
            if jsp_deps:
                self.extract_version(jsp_deps[0], ns, result["jsp_environment"], "jsp_version")
            return

        result["architecture"] = "无法确定项目架构"

    def detect_embedded_servlet_container(self, root, ns, result):
        # 检测Spring Boot内嵌的Servlet容器
        containers = {
            "tomcat": ["tomcat", "spring-boot-starter-tomcat"],
            "jetty": ["jetty", "spring-boot-starter-jetty"],
            "undertow": ["undertow", "spring-boot-starter-undertow"]
        }

        for container, keys in containers.items():
            for key in keys:
                deps = self.find_artifact(root, key, ns)
                if deps:
                    result["jsp_environment"]["servlet_container"] = container.capitalize()
                    self.extract_version(deps[0], ns, result["jsp_environment"], "container_version")
                    if container == "tomcat":
                        result["jsp_environment"]["has_jsp"] = True
                    return

    def detect_servlet_container(self, root, ns, result):
        # 检测外部Servlet容器
        containers = {
            "tomcat": ["tomcat", "tomcat-embed"],
            "jetty": ["jetty"],
            "undertow": ["undertow"],
            "weblogic": ["weblogic"],
            "websphere": ["websphere"]
        }

        for container, keys in containers.items():
            for key in keys:
                deps = self.find_artifact(root, key, ns)
                if deps:
                    result["jsp_environment"]["servlet_container"] = container.capitalize()
                    self.extract_version(deps[0], ns, result["jsp_environment"], "container_version")
                    if container == "tomcat":
                        result["jsp_environment"]["has_jsp"] = True
                    return

    def detect_persistence_framework(self, root, ns, result):
        # 检查 MyBatis-Plus (优先级最高)
        mybatis_plus_deps = self.find_artifact(root, "mybatis-plus-boot-starter", ns)
        if not mybatis_plus_deps:
            mybatis_plus_deps = self.find_artifact(root, "mybatis-plus", ns)

        if mybatis_plus_deps:
            result["persistence_framework"] = "MyBatis-Plus"
            self.extract_version(mybatis_plus_deps[0], ns, result, "mybatis-plus")
            return

        # 检查 MyBatis
        mybatis_deps = self.find_artifact(root, "mybatis", ns)
        if mybatis_deps:
            result["persistence_framework"] = "MyBatis"
            self.extract_version(mybatis_deps[0], ns, result, "mybatis")
            return

        # 检查 Hibernate
        hibernate_deps = self.find_artifact(root, "hibernate-core", ns)
        if hibernate_deps:
            result["persistence_framework"] = "Hibernate"
            self.extract_version(hibernate_deps[0], ns, result, "hibernate")
            return

        # 检查 Spring Data JPA
        spring_data_jpa_deps = self.find_artifact(root, "spring-data-jpa", ns)
        if spring_data_jpa_deps:
            result["persistence_framework"] = "Spring Data JPA"
            self.extract_version(spring_data_jpa_deps[0], ns, result, "spring-data-jpa")
            return

        # 检查 JDBC 驱动
        jdbc_drivers = ["mysql-connector-java", "ojdbc", "postgresql", "sqljdbc"]
        for driver in jdbc_drivers:
            deps = self.find_artifact(root, driver, ns)
            if deps:
                result["persistence_framework"] = "JDBC"
                self.extract_version(deps[0], ns, result, driver)
                return

        result["persistence_framework"] = "未检测到持久层框架或使用自定义实现"

    def extract_version(self, dep_element, ns, result, key):
        version = dep_element.find("ns:version", ns)
        if version is None:
            version = dep_element.find("version")
        if version is not None and version.text:
            version_text = self.resolve_version(version.text, dep_element, ns)
            result[key] = version_text
        else:
            # 处理继承自父POM的版本
            parent = dep_element.find("..//ns:parent", ns)
            if parent is None:
                parent = dep_element.find("..//parent")
            if parent is not None:
                version = parent.find("ns:version", ns)
                if version is None:
                    version = parent.find("version")
                if version is not None and version.text:
                    result[key] = version.text

    def analyze_dependencies(self, root, ns, result):
        components = [
            "fastjson", "shiro", "log4j", "log4j-core", "logback",
            "mysql-connector-java", "mybatis", "mybatis-plus",
            "druid", "swagger", "springfox", "spring-boot", "spring-webmvc",
            "servlet-api", "jsp-api"
        ]

        for component in components:
            deps = self.find_artifact(root, component, ns)
            if deps:
                self.extract_version(deps[0], ns, result["dependencies"], component)

    def resolve_version(self, version_text, element, ns):
        if version_text.startswith("${") and version_text.endswith("}"):
            prop_name = version_text[2:-1]

            # 检查当前元素的properties
            properties = element.find("..//ns:properties", ns)
            if properties is None:
                properties = element.find("..//properties")

            if properties is not None:
                prop = properties.find(f"ns:{prop_name}", ns)
                if prop is None:
                    prop = properties.find(prop_name)
                if prop is not None and prop.text:
                    return prop.text

            # 检查父pom的properties
            parent = element.find("..//ns:parent", ns)
            if parent is None:
                parent = element.find("..//parent")

            if parent is not None:
                parent_prop = parent.find(f"ns:{prop_name.split('.')[-1]}", ns)
                if parent_prop is None:
                    parent_prop = parent.find(prop_name.split('.')[-1])
                if parent_prop is not None and parent_prop.text:
                    return parent_prop.text

        return version_text

    def check_vulnerabilities(self, result):
        for lib, version in result["dependencies"].items():
            lib_lower = lib.lower()
            if "log4j-core" in lib_lower:
                lib_lower = "log4j"
            elif "mybatis-plus" in lib_lower:
                lib_lower = "mybatis"
            elif "springfox" in lib_lower or "swagger" in lib_lower:
                lib_lower = "swagger"

            if lib_lower in VULNERABILITY_DB:
                vuln_info = VULNERABILITY_DB[lib_lower]
                matched = False

                for vuln_version, details in vuln_info.items():
                    if vuln_version == "default":
                        continue

                    if "-" in vuln_version:  # 处理版本范围
                        start_ver, end_ver = vuln_version.split("-")
                        if self.compare_version_range(version, start_ver, end_ver):
                            matched = True
                            result["vulnerabilities"].append({
                                "library": lib,
                                "version": version,
                                "issues": details.get("issues", ["未知漏洞"]),
                                "status": "存在漏洞" if details.get("vulnerable", False) else "安全版本",
                                "severity": details.get("severity", "中危")
                            })
                            break
                    elif self.compare_versions(version, vuln_version):
                        matched = True
                        result["vulnerabilities"].append({
                            "library": lib,
                            "version": version,
                            "issues": details.get("issues", ["未知漏洞"]),
                            "status": "存在漏洞" if details.get("vulnerable", False) else "安全版本",
                            "severity": details.get("severity", "中危")
                        })
                        break

                if not matched and "default" in vuln_info:
                    result["vulnerabilities"].append({
                        "library": lib,
                        "version": version,
                        "issues": vuln_info["default"].get("issues", ["需要进一步检查"]),
                        "status": "可能存在问题",
                        "severity": vuln_info["default"].get("severity", "中危")
                    })

    def check_security_issues(self, root, ns, result):
        # 检查Druid未授权访问
        if "druid" in result["dependencies"]:
            result["security_issues"].append({
                "issue": "Druid未授权访问",
                "description": "Druid监控页面可能未配置访问控制，导致敏感信息泄露",
                "solution": "1. 升级Druid到最新版本\n2. 配置访问控制\n3. 在生产环境禁用监控页面",
                "severity": "高危"
            })

        # 检查Swagger未授权访问
        if any(lib in result["dependencies"] for lib in ["swagger", "springfox"]):
            result["security_issues"].append({
                "issue": "Swagger未授权访问",
                "description": "Swagger API文档可能未配置访问控制，导致API信息泄露",
                "solution": "1. 配置访问控制\n2. 在生产环境禁用Swagger UI\n3. 升级到Swagger 3.0+",
                "severity": "中危"
            })

        # 检查Spring Boot Actuator未授权访问
        if "spring-boot" in result["dependencies"] and result["architecture"] == "Spring Boot":
            result["security_issues"].append({
                "issue": "Spring Boot Actuator未授权访问",
                "description": "Actuator端点可能未配置访问控制，导致敏感信息泄露",
                "solution": "1. 配置management.endpoints.web.exposure.include\n2. 添加安全认证\n3. 禁用不必要的端点",
                "severity": "高危"
            })

    def compare_versions(self, v1, v2):
        try:
            v1_clean = re.sub(r'[^0-9.]', '', v1)
            v2_clean = re.sub(r'[^0-9.]', '', v2)

            v1_parts = list(map(int, v1_clean.split('.')))
            v2_parts = list(map(int, v2_clean.split('.')))

            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts += [0] * (max_len - len(v1_parts))
            v2_parts += [0] * (max_len - len(v2_parts))

            return v1_parts == v2_parts
        except:
            return v1 == v2

    def compare_version_range(self, version, start_ver, end_ver):
        try:
            v_clean = re.sub(r'[^0-9.]', '', version)
            v_parts = list(map(int, v_clean.split('.')))

            start_clean = re.sub(r'[^0-9.]', '', start_ver)
            start_parts = list(map(int, start_clean.split('.')))

            end_clean = re.sub(r'[^0-9.]', '', end_ver)
            end_parts = list(map(int, end_clean.split('.')))

            max_len = max(len(v_parts), len(start_parts), len(end_parts))
            v_parts += [0] * (max_len - len(v_parts))
            start_parts += [0] * (max_len - len(start_parts))
            end_parts += [0] * (max_len - len(end_parts))

            # 检查版本是否在范围内
            for v, s, e in zip(v_parts, start_parts, end_parts):
                if v < s:
                    return False
                if v > e:
                    return False

            return True
        except:
            return False

    def display_results(self, result):
        self.result_area.config(state=tk.NORMAL)
        self.result_area.delete(1.0, tk.END)

        # 项目架构信息
        self.result_area.insert(tk.END, "=== 项目架构分析 ===\n")
        self.result_area.insert(tk.END, f"检测到的架构: {result['architecture']}\n\n")

        # JSP环境信息
        self.result_area.insert(tk.END, "=== JSP解析环境 ===\n")
        if result["jsp_environment"]["has_jsp"]:
            self.result_area.insert(tk.END, "使用JSP: 是\n")
            if result["jsp_environment"]["servlet_container"]:
                self.result_area.insert(tk.END, f"Servlet容器: {result['jsp_environment']['servlet_container']}\n")
            if result["jsp_environment"].get("container_version"):
                self.result_area.insert(tk.END, f"容器版本: {result['jsp_environment']['container_version']}\n")
            if result["jsp_environment"].get("jsp_version"):
                self.result_area.insert(tk.END, f"JSP版本: {result['jsp_environment']['jsp_version']}\n")
        else:
            self.result_area.insert(tk.END, "使用JSP: 否\n")
        self.result_area.insert(tk.END, "\n")

        # 持久层框架
        self.result_area.insert(tk.END, "=== 持久层框架分析 ===\n")
        self.result_area.insert(tk.END, f"检测到的框架: {result['persistence_framework']}\n\n")

        # 依赖项
        self.result_area.insert(tk.END, "=== 检测到的依赖项 ===\n")
        for lib, version in result["dependencies"].items():
            self.result_area.insert(tk.END, f"{lib}: {version}\n")
        self.result_area.insert(tk.END, "\n")

        # 安全漏洞
        self.result_area.insert(tk.END, "=== 安全漏洞分析 ===\n")
        if not result["vulnerabilities"]:
            self.result_area.insert(tk.END, "未检测到已知漏洞组件\n")
        else:
            for vuln in result["vulnerabilities"]:
                self.result_area.insert(tk.END, f"组件: {vuln['library']} {vuln['version']}\n")
                self.result_area.insert(tk.END, f"状态: {vuln['status']} ({vuln['severity']})\n")
                if vuln["issues"]:
                    self.result_area.insert(tk.END, "问题: " + ", ".join(vuln["issues"]) + "\n")
                self.result_area.insert(tk.END, "-" * 80 + "\n")
        self.result_area.insert(tk.END, "\n")

        # 安全配置问题
        self.result_area.insert(tk.END, "=== 安全配置问题 ===\n")
        if not result["security_issues"]:
            self.result_area.insert(tk.END, "未检测到明显的安全配置问题\n")
        else:
            for issue in result["security_issues"]:
                self.result_area.insert(tk.END, f"问题: {issue['issue']} ({issue['severity']})\n")
                self.result_area.insert(tk.END, f"描述: {issue['description']}\n")
                self.result_area.insert(tk.END, f"解决方案:\n{issue['solution']}\n")
                self.result_area.insert(tk.END, "-" * 80 + "\n")

        # 时间戳
        self.result_area.insert(tk.END, f"\n分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.result_area.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = PomAnalyzerApp(root)
    root.mainloop()