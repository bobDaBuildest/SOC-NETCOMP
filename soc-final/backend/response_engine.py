import subprocess
import platform
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ResponseEngine")

class ResponseEngine:
    @staticmethod
    def block_ip(ip_address: str):
        system_os = platform.system()

        try:
            if system_os == "Windows":
                cmd = f"netsh advfirewall firewall add rule name='SOC_BLOCK_{ip_address}' dir=in action=block remoteip={ip_address}"
            else:
                cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"

            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"Blocked IP: {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
            return False

    @staticmethod
    def log_event(alert_id: str, action: str):
        with open("action_history.log", "a") as f:
            f.write(f"Alert: {alert_id} | Action: {action}\n")
