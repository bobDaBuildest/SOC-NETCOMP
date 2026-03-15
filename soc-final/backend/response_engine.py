import subprocess
import platform
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ResponseEngine")


class ResponseEngine:
    _blocked_ips = set()

    @classmethod
    def block_ip(cls, ip_address: str):
        system_os = platform.system()

        try:
            if system_os == "Windows":
                cmd = f"netsh advfirewall firewall add rule name='SOC_BLOCK_{ip_address}' dir=in action=block remoteip={ip_address}"
            else:
                cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"

            subprocess.run(cmd, shell=True, check=True)
            cls._blocked_ips.add(ip_address)
            logger.info(f"Blocked IP: {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
            return False

    @classmethod
    def get_status(cls):
        # In a real deployment, this would query the firewall management system.
        # Here we treat any blocked IPs as evidence the firewall is active.
        return {
            "active_firewalls": ["Cisco-ASA-Firewall-01"] if cls._blocked_ips else [],
            "blocked_ips": sorted(
                cls._blocked_ips),
        }

    @staticmethod
    def log_event(alert_id: str, action: str):
        with open("action_history.log", "a") as f:
            f.write(f"Alert: {alert_id} | Action: {action}\n")
