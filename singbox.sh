#!/usr/bin/env python3
"""
代理服务器配置脚本
用于自动配置系统参数、申请证书、设置代理服务
"""

import os
import sys
import subprocess
import json
import time
import logging
import socket
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any
from enum import Enum, auto

# 颜色定义
class Colors:
    """ANSI颜色代码"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# 日志级别颜色映射
LOG_COLORS = {
    logging.DEBUG: Colors.BLUE,
    logging.INFO: Colors.CYAN,
    logging.WARNING: Colors.YELLOW,
    logging.ERROR: Colors.RED,
    logging.CRITICAL: Colors.RED + Colors.BOLD
}

class LogFormatter(logging.Formatter):
    """自定义日志格式化器"""
    def format(self, record: logging.LogRecord) -> str:
        if record.levelno in LOG_COLORS:
            record.msg = f"{LOG_COLORS[record.levelno]}{record.msg}{Colors.ENDC}"
        return super().format(record)

class SetupStep(Enum):
    """配置步骤枚举"""
    DEPENDENCIES = auto()
    SYSTEM = auto()
    PORT_FORWARD = auto()
    ACME = auto()
    CERTIFICATE = auto()
    PROXY = auto()
    SERVICE = auto()

@dataclass
class Config:
    """配置数据类"""
    domain: str
    email: str
    password: str
    cert_dir: str
    acme_dir: str

class ProxySetup:
    """代理服务器配置类"""
    
    # 常量定义
    SERVER_CONFIG_PATH = "/etc/sing-box/config.json"
    CLIENT_CONFIG_DIR = "/etc/sing-box/client"
    SYSCTL_CONF = "/etc/sysctl.d/99-sysctl.conf"
    NFTABLES_CONF = "/etc/nftables.conf"
    NFTABLES_RULES_DIR = "/etc/nftables.d"
    PORT_FORWARD_RULES = "/etc/nftables.d/port-forward.nft"
    
    # 系统参数
    SYSCTL_PARAMS = [
        "net.core.rmem_max=2500000",
        "net.core.wmem_max=2500000",
        "net.ipv4.tcp_congestion_control=bbr",
        "net.ipv4.tcp_fastopen=3",
        "net.ipv4.tcp_slow_start_after_idle=0",
        "net.ipv4.tcp_notsent_lowat=16384",
        "net.ipv4.tcp_mtu_probing=1",
        "net.ipv4.tcp_rmem='4096 87380 16777216'",
        "net.ipv4.tcp_wmem='4096 87380 16777216'",
        "net.core.default_qdisc=fq"
    ]
    
    # 依赖项
    DEPENDENCIES = {
        "socat": "socat",
        "nft": "nftables",
        "curl": "curl",
        "wget": "wget",
        "cron": "cron",
        "openssl": "openssl"
    }
    
    def __init__(self):
        """初始化配置类"""
        self._setup_logging()
        self.config: Optional[Config] = None
        self.is_sudo: bool = False
        self.work_dir: str = os.path.abspath(os.getcwd())
        self.client_config_path: str = os.path.join(self.CLIENT_CONFIG_DIR, "config.json")

    def _setup_logging(self) -> None:
        """配置日志系统"""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(LogFormatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(console_handler)

    def _get_interface_ip(self) -> str:
        """获取本机网卡IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "无法获取"

    def _check_sudo(self) -> bool:
        """检查sudo权限"""
        try:
            if os.geteuid() == 0:
                return True
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                text=True
            )
            self.is_sudo = result.returncode == 0
            return self.is_sudo
        except Exception:
            return False

    def _run_command(self, command: str, shell: bool = True) -> Tuple[bool, str]:
        """执行命令并返回结果"""
        try:
            if self.is_sudo and not os.geteuid() == 0:
                command = f"sudo {command}"
            
            result = subprocess.run(
                command,
                shell=shell,
                check=True,
                capture_output=True,
                text=True
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr

    def _get_unique_filename(self, base_path: str) -> str:
        """获取唯一的文件名，如果文件已存在则添加数字后缀"""
        if not os.path.exists(base_path):
            return base_path
            
        directory = os.path.dirname(base_path)
        filename = os.path.basename(base_path)
        name, ext = os.path.splitext(filename)
        
        counter = 1
        while True:
            new_path = os.path.join(directory, f"{name}_{counter}{ext}")
            if not os.path.exists(new_path):
                return new_path
            counter += 1

    def _print_welcome(self) -> None:
        """打印欢迎信息"""
        self.logger.info(f"""
{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}
{Colors.BOLD}{Colors.CYAN}代理服务器配置脚本{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}

{Colors.BOLD}功能：{Colors.ENDC}
{Colors.GREEN}  • 系统网络参数优化{Colors.ENDC}
{Colors.GREEN}  • 端口转发规则配置{Colors.ENDC}
{Colors.GREEN}  • SSL证书申请{Colors.ENDC}
{Colors.GREEN}  • 代理服务部署{Colors.ENDC}

{Colors.BOLD}前置条件：{Colors.ENDC}
{Colors.YELLOW}  • 域名已解析到本机IP{Colors.ENDC}
{Colors.YELLOW}  • 准备SSL证书申请邮箱{Colors.ENDC}
{Colors.YELLOW}  • 具备sudo权限{Colors.ENDC}

{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}
""")

    def _print_system_info(self) -> None:
        """打印系统信息"""
        self.logger.info(f"""
{Colors.BOLD}系统信息：{Colors.ENDC}
{Colors.CYAN}  • 本机IP: {self._get_interface_ip()}{Colors.ENDC}
{Colors.CYAN}  • 系统时间: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}
""")

    def _check_dependencies(self) -> bool:
        """检查并安装依赖"""
        self.logger.info("检查系统依赖...")
        
        missing = [
            pkg for cmd, pkg in self.DEPENDENCIES.items()
            if not self._run_command(f"which {cmd}")[0]
        ]

        if missing:
            self.logger.info(f"安装依赖: {', '.join(missing)}")
            success, output = self._run_command(
                f"apt-get update && apt-get install -y {' '.join(missing)}"
            )
            if not success:
                self.logger.error(f"依赖安装失败: {output}")
                return False

        if not self._run_command("systemctl is-active nftables")[0]:
            self.logger.info("启动nftables服务...")
            if not self._run_command("systemctl enable nftables && systemctl start nftables")[0]:
                self.logger.error("nftables服务启动失败")
                return False

        return True

    def _setup_system(self) -> bool:
        """配置系统参数"""
        self.logger.info("配置系统参数...")
        
        existing_params = set()
        if os.path.exists(self.SYSCTL_CONF):
            with open(self.SYSCTL_CONF, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        existing_params.add(line)

        with open(self.SYSCTL_CONF, "a") as f:
            for param in self.SYSCTL_PARAMS:
                if param not in existing_params:
                    f.write(f"\n{param}")

        for param in self.SYSCTL_PARAMS:
            if not self._run_command(f"sysctl -w {param}")[0]:
                self.logger.warning(f"参数设置失败: {param}")

        return True

    def _setup_port_forward(self) -> bool:
        """配置端口转发"""
        self.logger.info("配置端口转发...")

        self._run_command(f"mkdir -p {self.NFTABLES_RULES_DIR}")

        nft_script = """#!/usr/sbin/nft -f
table ip nat {
    chain prerouting {
        type nat hook prerouting priority 0;
        policy accept;
        udp dport 20000-50000 redirect to :8443
    }
}
"""

        if not os.path.exists(self.PORT_FORWARD_RULES):
            with open(self.PORT_FORWARD_RULES, "w") as f:
                f.write(nft_script)
        else:
            self.logger.info("端口转发规则已存在")

        if not os.path.exists(self.NFTABLES_CONF):
            default_config = """#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0;
        policy accept;
    }
    chain forward {
        type filter hook forward priority 0;
        policy accept;
    }
    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
"""
            with open(self.NFTABLES_CONF, "w") as f:
                f.write(default_config)
        else:
            self.logger.info("nftables配置已存在")

        include_line = f'include "{self.PORT_FORWARD_RULES}"'
        with open(self.NFTABLES_CONF, "r") as f:
            content = f.read()

        if include_line not in content:
            with open(self.NFTABLES_CONF, "a") as f:
                f.write(f"\n{include_line}\n")
            self.logger.info("添加端口转发规则")

        return self._run_command(f"nft -f {self.NFTABLES_CONF}")[0]

    def _setup_acme(self) -> bool:
        """配置acme.sh"""
        self.logger.info("配置acme.sh...")

        home_dir = os.path.expanduser("~")
        self.config.acme_dir = os.path.join(home_dir, ".acme.sh")

        if not os.path.exists(self.config.acme_dir):
            self.logger.info("安装acme.sh...")
            install_cmd = f"""
            cd {home_dir}
            curl -s https://get.acme.sh | sh -s email={self.config.email}
            """
            if not self._run_command(install_cmd)[0]:
                self.logger.error("acme.sh安装失败")
                return False

            if not os.path.exists(f"{self.config.acme_dir}/acme.sh"):
                self.logger.error("acme.sh安装验证失败")
                return False

            self._run_command(f"chmod +x {self.config.acme_dir}/acme.sh")

        os.environ['HOME'] = home_dir
        os.environ['PATH'] = f"{self.config.acme_dir}:{os.environ['PATH']}"

        time.sleep(2)

        if not self._run_command(f"{self.config.acme_dir}/acme.sh --version")[0]:
            self.logger.error("acme.sh安装验证失败")
            return False

        commands = [
            f"{self.config.acme_dir}/acme.sh --upgrade --auto-upgrade",
            f"{self.config.acme_dir}/acme.sh --set-default-ca --server letsencrypt",
            f"{self.config.acme_dir}/acme.sh --register-account -m {self.config.email}"
        ]

        for cmd in commands:
            for _ in range(3):
                if self._run_command(cmd)[0]:
                    break
                time.sleep(1)
            else:
                self.logger.warning(f"acme.sh配置命令失败: {cmd}")

        return True

    def _issue_certificate(self) -> bool:
        """申请证书"""
        self.logger.info(f"申请证书: {self.config.domain}")

        try:
            ip = socket.gethostbyname(self.config.domain)
            self.logger.info(f"域名解析到: {ip}")
        except socket.gaierror:
            self.logger.error("域名解析失败")
            return False

        if self._run_command("lsof -i :80")[0]:
            self.logger.error("80端口被占用")
            return False

        self.config.cert_dir = f"{self.config.acme_dir}/{self.config.domain}_ecc"
        self._run_command(f"mkdir -p {self.config.cert_dir}")

        issue_cmd = f"""
        cd {os.path.expanduser('~')}
        {self.config.acme_dir}/acme.sh --issue -d {self.config.domain} --standalone --force --debug
        """

        success, output = self._run_command(issue_cmd)
        if not success:
            self.logger.error("证书申请失败")
            self.logger.error(f"错误详情：\n{Colors.RED}{output}{Colors.ENDC}")
            return False

        install_cmd = f"""
        cd {os.path.expanduser('~')}
        {self.config.acme_dir}/acme.sh --install-cert -d {self.config.domain} \
            --key-file {self.config.cert_dir}/{self.config.domain}.key \
            --fullchain-file {self.config.cert_dir}/fullchain.cer
        """

        success, output = self._run_command(install_cmd)
        if not success:
            self.logger.error("证书安装失败")
            self.logger.error(f"错误详情：\n{Colors.RED}{output}{Colors.ENDC}")
            return False

        return True

    def _get_server_config(self) -> Dict[str, Any]:
        """获取服务器配置"""
        return {
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "listen": "::",
                    "listen_port": 8080,
                    "network": "tcp",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": self.config.password,
                    "multiplex": {"enabled": True}
                },
                {
                    "type": "hysteria2",
                    "listen": "::",
                    "listen_port": 8443,
                    "users": [{"name": "xing", "password": self.config.password}],
                    "tls": {
                        "enabled": True,
                        "server_name": self.config.domain,
                        "key_path": f"{self.config.cert_dir}/{self.config.domain}.key",
                        "certificate_path": f"{self.config.cert_dir}/fullchain.cer"
                    }
                }
            ],
            "outbounds": [{"type": "direct"}]
        }

    def _get_client_config(self) -> Dict[str, Any]:
        """获取客户端配置"""
        subdomain = self.config.domain.split('.')[0]
        return {
            "outbounds": [
                {
                    "type": "urltest",
                    "tag": subdomain,
                    "outbounds": [f"ss2022-{subdomain}", f"hy2-{subdomain}"]
                },
                {
                    "type": "shadowsocks",
                    "tag": f"ss2022-{subdomain}",
                    "server": self.config.domain,
                    "server_port": 8080,
                    "method": "2022-blake3-aes-128-gcm",
                    "password": self.config.password,
                    "multiplex": {"enabled": True}
                },
                {
                    "type": "hysteria2",
                    "tag": f"hy2-{subdomain}",
                    "server": self.config.domain,
                    "server_port": 8443,
                    "up_mbps": 300,
                    "down_mbps": 400,
                    "password": self.config.password,
                    "tls": {
                        "enabled": True,
                        "server_name": self.config.domain
                    }
                }
            ]
        }

    def _setup_proxy(self) -> bool:
        """配置代理服务"""
        self.logger.info("配置代理服务...")

        if not self._run_command("sing-box version")[0]:
            self.logger.info("安装sing-box...")
            if not self._run_command("curl -fsSL https://sing-box.app/install.sh | sh")[0]:
                self.logger.error("sing-box安装失败")
                return False

        # 创建客户端配置目录
        os.makedirs(self.CLIENT_CONFIG_DIR, exist_ok=True)

        # 保存服务器配置
        os.makedirs("/etc/sing-box", exist_ok=True)
        with open(self.SERVER_CONFIG_PATH, "w") as f:
            json.dump(self._get_server_config(), f, indent=2)

        # 保存客户端配置
        self.client_config_path = self._get_unique_filename(self.client_config_path)
        if self.client_config_path != os.path.join(self.CLIENT_CONFIG_DIR, "config.json"):
            self.logger.info(f"配置文件已存在，将保存为: {os.path.basename(self.client_config_path)}")

        with open(self.client_config_path, "w") as f:
            json.dump(self._get_client_config(), f, indent=2)

        return True

    def _setup_service(self) -> bool:
        """配置服务"""
        self.logger.info("配置服务...")

        self._run_command(
            f"{self.config.acme_dir}/acme.sh --install-cert -d {self.config.domain} "
            f"--key-file {self.config.cert_dir}/{self.config.domain}.key "
            f"--fullchain-file {self.config.cert_dir}/fullchain.cer "
            f"--reloadcmd 'systemctl restart sing-box'"
        )

        commands = [
            "systemctl enable sing-box",
            "systemctl restart sing-box"
        ]

        for cmd in commands:
            if not self._run_command(cmd)[0]:
                self.logger.error(f"服务命令失败: {cmd}")
                return False

        return True

    def _print_config_summary(self) -> None:
        """打印配置摘要"""
        self.logger.info(f"""
{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}
{Colors.BOLD}{Colors.GREEN}配置完成{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}

{Colors.BOLD}服务器配置：{Colors.ENDC}
{Colors.CYAN}  • 域名: {self.config.domain}{Colors.ENDC}
{Colors.CYAN}  • 邮箱: {self.config.email}{Colors.ENDC}
{Colors.CYAN}  • 密码: {self.config.password}{Colors.ENDC}
{Colors.CYAN}  • Shadowsocks: 8080 (TCP){Colors.ENDC}
{Colors.CYAN}  • Hysteria2: 8443 (UDP){Colors.ENDC}

{Colors.BOLD}客户端配置：{Colors.ENDC}
{Colors.YELLOW}  • 配置文件: {self.client_config_path}{Colors.ENDC}
{Colors.YELLOW}  • 确保域名解析正确{Colors.ENDC}

{Colors.BOLD}客户端完整配置：{Colors.ENDC}
{Colors.CYAN}{json.dumps(self._get_client_config(), indent=2)}{Colors.ENDC}

{Colors.BOLD}注意事项：{Colors.ENDC}
{Colors.GREEN}  • 证书自动续期{Colors.ENDC}
{Colors.GREEN}  • 配置文件: {self.SERVER_CONFIG_PATH}{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}
""")

    def run(self) -> bool:
        """运行配置流程"""
        self._print_welcome()
        self._print_system_info()

        if not self._check_sudo():
            self.logger.error("需要sudo权限")
            return False

        self.logger.info(f"\n{Colors.BOLD}请输入配置信息：{Colors.ENDC}\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        domain = input(f"{Colors.CYAN}  • 域名 (用于SSL证书和客户端连接): {Colors.ENDC}").strip()
        if not domain:
            self.logger.error("域名不能为空")
            return False

        email = input(f"{Colors.CYAN}  • 邮箱 (用于Let's Encrypt证书申请): {Colors.ENDC}").strip()
        if not email:
            self.logger.error("邮箱不能为空")
            return False

        password = subprocess.run(
            ['openssl', 'rand', '-base64', '16'],
            capture_output=True,
            text=True
        ).stdout.strip()

        self.config = Config(
            domain=domain,
            email=email,
            password=password,
            cert_dir="",
            acme_dir=""
        )

        self.logger.info(f"\n{Colors.BOLD}开始配置...{Colors.ENDC}\n{Colors.HEADER}{'='*60}{Colors.ENDC}")

        steps = [
            (self._check_dependencies, SetupStep.DEPENDENCIES),
            (self._setup_system, SetupStep.SYSTEM),
            (self._setup_port_forward, SetupStep.PORT_FORWARD),
            (self._setup_acme, SetupStep.ACME),
            (self._issue_certificate, SetupStep.CERTIFICATE),
            (self._setup_proxy, SetupStep.PROXY),
            (self._setup_service, SetupStep.SERVICE)
        ]

        for step_func, step in steps:
            self.logger.info(f"{Colors.BOLD}开始{step.name}...{Colors.ENDC}")
            if not step_func():
                self.logger.error(f"{step.name}失败")
                return False
            self.logger.info(f"{Colors.GREEN}{step.name}完成{Colors.ENDC}")

        self._print_config_summary()
        return True

def main():
    """主函数"""
    setup = ProxySetup()
    if not setup.run():
        sys.exit(1)

if __name__ == "__main__":
    main()
