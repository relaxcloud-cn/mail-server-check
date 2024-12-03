from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class RISK_LEVEL:
    LOW = "低风险"
    MEDIUM = "中风险"
    HIGH = "高风险"


class Risk(BaseModel):
    risk_level: str  # 1: 低风险 2: 中风险 3: 高风险
    risk_name: str  # 风险名称
    risk_category: str  # 风险类别
    description: str  # 风险描述
    fix_advice: str  # 修复建议
    envidance: str = ""  # 证据
    host: str = ""  # 风险主机
    check_time: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 检查时间


class RISK_ITEM(Enum):
    NO_SPF_RECORD = "NO_SPF_RECORD"
    SOFTFAIL_SPF = "SOFTFAIL_SPF"
    SPF_SYNTAX_ERROR = "SPF_SYNTAX_ERROR"
    SPF_SCOPE_TOO_LARGE = "SPF_SCOPE_TOO_LARGE"
    STARTTLS_DOWNGRADE = "STARTTLS_DOWNGRADE"
    DMARC_CONFIG_ERROR = "DMARC_CONFIG_ERROR"
    DMARC_NOT_CONFIG = "DMARC_NOT_CONFIG"
    DMARC_SYNTAX_ERROR = "DMARC_SYNTAX_ERROR"
    OLD_SSL_VERSION = "OLD_SSL_VERSION"
    SMTP_OPEN_RELAY = "SMTP_OPEN_RELAY"
    SMTP_ENUM_USERS = "SMTP_ENUM_USERS"


def what_risk(risk_name: RISK_ITEM) -> Risk:
    match risk_name:
        case RISK_ITEM.NO_SPF_RECORD:
            return Risk(
                risk_level=RISK_LEVEL.HIGH,
                risk_name="SPF未配置(实际发件人伪造风险)",
                risk_category="配置不当",
                description="SPF未配置会导致当前域名下的发件人可被任意伪造风险",
                fix_advice="域名配置SPF记录",
            )
        case RISK_ITEM.SOFTFAIL_SPF:
            return Risk(
                risk_level=RISK_LEVEL.LOW,
                risk_name="SPF软拒绝(实际发件人伪造风险)",
                risk_category="配置不当",
                description="SPF软拒绝会导致接收方遇到有软拒绝的域名没有通过SPF校验，但任然放行或者标记为垃圾邮件，从而造成当前域名下的发件人被任意伪造风险",
                fix_advice="域名配置SPF记录 ~all 的配置设置 为 -all",
            )
        case RISK_ITEM.SPF_SYNTAX_ERROR:
            return Risk(
                risk_level=RISK_LEVEL.HIGH,
                risk_name="SPF语法错误(实际发件人伪造风险)",
                risk_category="配置不当",
                description="SPF配置语法不正确会导致当前域名下的发件人可被任意伪造风险",
                fix_advice="域名配置SPF记录",
            )
        case RISK_ITEM.SPF_SCOPE_TOO_LARGE:
            return Risk(
                risk_level=RISK_LEVEL.HIGH,
                risk_name="SPF范围过大(实际发件人伪造风险)",
                risk_category="配置不当",
                description="SPF范围过大可能导致当前域名下的发件人可被任意伪造风险",
                fix_advice="SPF记录仅配置邮件服务器ip或者组织域ip网段",
            )
        case RISK_ITEM.STARTTLS_DOWNGRADE:
            return Risk(
                risk_level=RISK_LEVEL.LOW,
                risk_name="STARTTLS 协议降级风险",
                risk_category="配置不当",
                description="STARTTLS降级攻击可能使邮件传输变为明文形式，从而暴露敏感数据并使通信容易受到窃听和篡改。",
                fix_advice="禁止邮件服务器开启明文登陆，并配置邮件服务器，使其在发送和接收邮件时强制使用TLS连接，拒绝非加密的连接",
            )
        case RISK_ITEM.DMARC_CONFIG_ERROR:
            return Risk(
                risk_level=RISK_LEVEL.MEDIUM,
                risk_name="DMARC策略配置不当(显示发件人伪造风险)",
                risk_category="配置不当",
                description="DMARC未配置或者配置策略为none会导致当前域名下的邮箱显示发件人可被任意伪造",
                fix_advice="配置DMARC策略并且至少设置策略为quarantine/reject以验证发件人身份，隔离或拒绝邮件伪造的邮件，并增强电子邮件系统的整体安全性。",
            )
        case RISK_ITEM.DMARC_NOT_CONFIG:
            return Risk(
                risk_level=RISK_LEVEL.MEDIUM,
                risk_name="DMARC未配置(显示发件人伪造风险)",
                risk_category="配置不当",
                description="DMARC未配置会导致当前域名下的邮箱显示发件人可被任意伪造",
                fix_advice="域名配置标准的DMARC记录",
            )
        case RISK_ITEM.DMARC_SYNTAX_ERROR:
            return Risk(
                risk_level=RISK_LEVEL.MEDIUM,
                risk_name="DMARC配置语法错误(显示发件人伪造风险)",
                risk_category="配置不当",
                description="DMARC语法错误使DMARC失效，从而导致当前域名下的邮箱显示发件人可被任意伪造",
                fix_advice="域名配置标准的DMARC记录",
            )
        case RISK_ITEM.OLD_SSL_VERSION:
            return Risk(
                risk_level=RISK_LEVEL.LOW,
                risk_name="tls证书使用不安全的旧版协议",
                risk_category="配置不当",
                description="邮件域名使用的证书未禁用不安全的旧版协议，可能导致数据泄露、中间人攻击和身份冒用等安全风险。",
                fix_advice="禁用如SSL 2.0、SSL 3.0等早期版本的TLS协议",
            )
        case RISK_ITEM.SMTP_OPEN_RELAY:
            return Risk(
                risk_level=RISK_LEVEL.HIGH,
                risk_name="邮服开放中继风险(实际发件人伪造风险)",
                risk_category="配置不当",
                description="配置为开放中继的邮件服务器允许通过开放中继服务器透明地重新路由来自任何源的邮件。这种行为掩盖了邮件的原始源，并使它看上去像是来自开放中继服务器的邮件。从而攻击者将开放的中继用作其与目标收件人之间的中转点，从而通过该点匿名地以当前邮件域分发大量的恶意邮件。",
                fix_advice="设置外来中继控制定义服务器可以将消息中继到哪些主机以及可以从哪些主机中继消息。",
            )
        case RISK_ITEM.SMTP_ENUM_USERS:
            return Risk(
                risk_level=RISK_LEVEL.LOW,
                risk_name="账户可被枚举风险",
                risk_category="配置不当",
                description="因邮件服务器配置不当导致账户可被爆破探测，可能使攻击者枚举到邮件账号，从而对邮件域内的用户发送钓鱼邮件或垃圾邮件",
                fix_advice="关闭域下邮件服务器EXPN/VRFY命令。配置邮件服务器返回信息描述更加模糊。",
            )

    raise ValueError(f"Unknow risk {risk_name}")
