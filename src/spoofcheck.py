import argparse
import datetime
import os
import socket
import ssl
from typing import List, Optional, Tuple
import itertools

import checkdmarc
import pandas as pd
from checkdmarc import dmarc, json, spf
from checkdmarc.dmarc import (
    DMARCRecordNotFound,
    DMARCSyntaxError,
    InvalidDMARCReportURI,
)
from checkdmarc.spf import SPFRecordNotFound, SPFSyntaxError
from loguru import logger
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote

from plugins.smtp_enum_users import enumerate_smtp_users
from report import RISK_ITEM, Risk, what_risk


class SpoofCheck:

    def __init__(self):
        if not os.path.exists("reports"):
            os.mkdir("reports")
        self.check_ports = [25, 465, 587]
        self.nameservers = ["8.8.8.8", "114.114.114.114"]

        self.user_discover = ["postmaster", "admin", "guest", "welcome"]

    def find_mx_domains(self, domain: str) -> List[str]:
        """
        查找 MX 记录对应的域名
        """
        # 这里不做异常捕获，有问题直接抛出即可
        mx_domains = [mx_domain["hostname"] for mx_domain in spf.get_mx_records(domain, nameservers=self.nameservers)]
        assert mx_domains, f"{domain} 未找到 MX 记录"
        return mx_domains

    def is_exist_spf_spoof(self, domain: str) -> Optional[Risk]:
        """
        检查 SPF 配置 是否造成了实际发件人伪造
        ---
        存在以下情况会造成伪造：
        - 没有 SPF 记录
        - SPF 记录设置为 “~all” 软拒绝
        - SPF 语法错误
        - SPF 范围过大
        """
        logger.info("[spf_spoof] 开始检查 {}", domain)
        try:
            response = spf.get_spf_record(domain, nameservers=self.nameservers)
            if response["parsed"]["all"] == "softfail":
                risk = what_risk(RISK_ITEM.SOFTFAIL_SPF)
                risk.envidance = response["record"]
                risk.host = domain
                return risk
            # TODO: SPF 范围过大
        except SPFRecordNotFound as e:
            logger.info("[spf] {}", e)
            risk = what_risk(RISK_ITEM.NO_SPF_RECORD)
            risk.envidance = "SPF 未配置"
            risk.host = domain
            return risk
        except SPFSyntaxError as e:
            logger.info("[spf] {}", e)
            spf_record = [i for i in spf.get_txt_records(domain, nameservers=self.nameservers) if "spf" in i.lower()]
            spf_record = spf_record[0] if spf_record else "SPF 未配置"
            risk = what_risk(RISK_ITEM.SPF_SYNTAX_ERROR)
            risk.envidance = spf_record
            risk.host = domain
            return risk
        except Exception as e:
            logger.error("[spf] {}", e)

    def is_exist_dmarc_spoof(self, domain: str) -> Optional[Risk]:
        """
        检查 DMARC 配置 是否造成了显示发件人伪造
        ---
        存在以下情况会造成伪造：
        - 没有 DMARC 记录
        - DMARC 记录设置为 “p=none” 不做处理
        """
        logger.info("[dmarc_spoof] 开始检查 {}", domain)
        try:
            response = dmarc.get_dmarc_record(domain, nameservers=self.nameservers)
            if response["parsed"]["tags"]["p"]["value"] == "none":
                logger.info("[dmarc] {} {}", domain, "p=none")
                risk = what_risk(RISK_ITEM.DMARC_CONFIG_ERROR)
                risk.envidance = response["record"]
                risk.host = domain
                return risk
        except DMARCRecordNotFound as e:
            logger.info("[dmarc] {}", e)
            risk = what_risk(RISK_ITEM.DMARC_NOT_CONFIG)
            risk.envidance = "DMARC 未配置"
            risk.host = domain
            return risk
        except InvalidDMARCReportURI as e:
            logger.info("[dmarc] {}", e)
            res = checkdmarc.check_dmarc(domain, nameservers=self.nameservers)
            risk = what_risk(RISK_ITEM.DMARC_CONFIG_ERROR)
            risk.envidance = res["record"]
            risk.fix_advice = str(e)
            risk.host = domain
            return risk
        except DMARCSyntaxError as e:
            logger.info("[dmarc] {}", e)
            res = checkdmarc.check_dmarc(domain, nameservers=self.nameservers)
            risk = what_risk(RISK_ITEM.DMARC_SYNTAX_ERROR)
            risk.envidance = res["record"]
            risk.fix_advice = str(e)
            risk.host = domain
            return risk
        except Exception as e:
            logger.error("[dmarc] {}", e)

    def has_starttls_downgrade(self, domain: str) -> Optional[Risk]:
        """
        检查 STARTTLS 协议是否被降级
        ---
        存在以下情况会被降级：
        - 服务器支持 STARTTLS 协议，但是没有强制使用(允许AUTH LOGIN PLAIN)
        """
        for port in self.check_ports:
            logger.info("[starttls_downgrade] 开始检查 {}:{}", domain, port)
            try:
                with remote(domain, port, timeout=2) as r:
                    resp = r.recvline()
                    logger.info("[starttls_downgrade] {}", resp)
                    r.sendline(b"AUTH LOGIN PLAIN")
                    resp = r.recvline().decode()
                    logger.info("[starttls_downgrade] {}", resp)
                    if "334" in resp:
                        risk = what_risk(RISK_ITEM.STARTTLS_DOWNGRADE)
                        risk.envidance = resp
                        risk.host = domain
                        return risk
            except Exception as e:
                # 这里不关注失败
                logger.debug("[starttls_downgrade] {}", e)
        return None

    def get_brand(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """
        获取品牌以及banner信息
        """
        mx_domains = self.find_mx_domains(domain)
        logger.info("[+] Mx domains: {}", mx_domains)
        for mx_domain, port in itertools.product(mx_domains, self.check_ports):
            logger.info("[recon] 开始检查 {}:{}", mx_domain, port)
            try:
                with remote(mx_domain, port, timeout=2) as r:
                    banner = str(r.recvline().decode())
                    brand = self._get_brand(banner)
                    if brand == "Unknown":
                        brand = self._get_brand(mx_domain)
                    return brand, banner
            except Exception as e:
                # 这里不关注失败
                logger.debug("[starttls_downgrade] {}", e)
        return None, None

    def _get_brand(self, fingerprint: str) -> str:
        fingermap = {
                "coremail": "Coremail",
                "qq": "腾讯邮箱",
                "163": "网易邮箱",
                "netease": "网易邮箱",
                "richmail": "彩讯邮箱",
                "eyou": "亿邮",
                "anymacro": "安宁",
                "outlook": "Exchange",
                "feishu": "飞书",
        }
        for finger, brand in fingermap.items():
            if finger in fingerprint:
                return brand
        return "Unknown"

    def is_used_old_ssl_version(self, domain: str) -> Optional[Risk]:
        """
        检查 SSL/TLS 协议是否使用了过旧的版本
        """

        old_versions = {
            ssl.PROTOCOL_SSLv23,
            ssl.PROTOCOL_TLSv1,
            ssl.PROTOCOL_TLSv1_1,
        }

        for port in self.check_ports:
            logger.info("[old-ssl-version] 开始检查 {}:{}", domain, port)
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        if ssock.version() in old_versions:
                            return what_risk(RISK_ITEM.OLD_SSL_VERSION)
            except Exception as e:
                logger.error("[ssl] {}", e)
        return None

    def has_smtp_open_relay(self, domain: str) -> Optional[Risk]:
        """
        检查是否存在邮件中继
        """
        for port in self.check_ports:
            logger.info("[smtp-open-relay] 开始检查 {}:{}", domain, port)
            io = process(
                ["nmap", "-p", str(port), "--script", "smtp-open-relay.nse", domain]
            )
            response = io.recvallS()
            if "Server is an open relay" in response:
                risk = what_risk(RISK_ITEM.SMTP_OPEN_RELAY)
                risk.envidance = response
                risk.host = domain
                return risk
        return None

    def has_smtp_enum_users(self, mx_domain: str, root_domain: str) -> Optional[Risk]:
        """
        检查是否存在用户枚举
        """
        for port in self.check_ports:
            logger.info("[smtp-enum-users] 开始检查 {}:{}", mx_domain, port)
            users = enumerate_smtp_users(
                mx_domain, port, root_domain, self.user_discover
            )
            if users:
                risk = what_risk(RISK_ITEM.SMTP_ENUM_USERS)
                risk.envidance = json.dumps(users, ensure_ascii=False)
                risk.host = mx_domain
                return risk
        return None

    def check(self, domain: str, enumerate_users: bool = False):
        mx_domains = self.find_mx_domains(domain)
        logger.info("[+] Mx domains: {}", mx_domains)
        risks = []
        for func in [
            self.is_exist_spf_spoof,
            self.is_exist_dmarc_spoof,
        ]:
            risk = func(domain)
            if risk:
                risks.append(risk)

        for mx_domain in mx_domains:
            for func in [
                self.has_starttls_downgrade,
                # self.is_used_old_ssl_version,
                self.has_smtp_open_relay,
            ]:
                risk = func(mx_domain)
                if risk:
                    risks.append(risk)
            if enumerate_users:
                try:
                    risk = self.has_smtp_enum_users(mx_domain, domain)
                    if risk:
                        risks.append(risk)
                except Exception as e:
                    logger.debug("[-] 用户枚举失败: {}", e)

        if not risks:
            logger.info("[+] 检查完成未发现风险")
            return None
        logger.info("[+] 检查完成, 风险数量: {}", len(risks))
        risk_df = pd.DataFrame([dict(risk) for risk in risks])
        return risk_df

    def report(
        self,
        domain: str,
        filename: Optional[str] = None,
        dir: Optional[str] = None,
        enumerate_users: bool = False,
    ):
        """
        输出检查报告
        """
        risk_df = self.check(domain, enumerate_users=enumerate_users)
        if risk_df is None:
            return risk_df
        if dir:
            if not os.path.exists(f"reports/{dir}"):
                os.mkdir(f"reports/{dir}")
            report_filename = f"reports/{dir}/{domain}.csv"
        else:
            report_filename = filename or f"reports/{domain}.csv"
        risk_df.to_csv(report_filename, index=False)
        logger.info("[+] 报告已保存到 {}", report_filename)
        return risk_df

def handler_check(args):
    args.output = ""
    sc = SpoofCheck()
    reports = []

    # TODO: 多线程并发
    if args.domain:
        try:
            reports.append(
                sc.report(
                    args.domain, args.output, enumerate_users=args.enumerate_users
                )
            )
        except Exception as e:
            logger.error("[-] 检查失败,可能{}没有MX记录: {}", args.domain, e)

    if args.domains:
        with open(args.domains, encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                try:
                    report = sc.report(
                        domain,
                        filename=args.output,
                        enumerate_users=args.enumerate_users,
                    )
                    if report:
                        reports.append(report)
                except Exception as e:
                    logger.error("[-] 检查失败,可能{}没有MX记录: {}", domain, e)

    if args.summary:
        final_df = pd.concat(reports, ignore_index=True)
        aggregated_df = (
            final_df.groupby("domain")["risk_name"]
            .agg(lambda x: ",".join(x))
            .reset_index()
        )
        aggregated_df.to_csv(
            f"summary_{datetime.datetime.today().strftime('%H_%M_%S')}.csv"
        )

def handler_recon(args):
    sc = SpoofCheck()
    reports = []
    if args.domain:
        if args.banner:
            brand, banner = sc.get_brand(args.domain)
            print(args.domain, brand, banner)
            reports.append({
                    "domain": args.domain,
                    "banner": banner,
                    "brand": brand
                    })
    if args.domains:
        for domain in args.domains:
            with open(args.domains, encoding="utf-8") as f:
                for line in f:
                    domain = line.strip()
                    if args.banner:
                        brand, banner = sc.get_brand(domain)
                        print(domain, brand, banner)
                        reports.append({
                                "domain": domain,
                                "banner": banner,
                                "brand": brand
                                })
    if args.filename:
        pd.DataFrame(reports).to_csv(args.filename, index=False)


def main():
    argparser = argparse.ArgumentParser(add_help=False)
    argparser.add_argument("-d", "--domain", help="域名")
    argparser.add_argument("-dL", "--domains", help="域名文件")
    sub_parsers = argparser.add_subparsers(title="subcommands", description="valid subcommands", help="sub-command help")

    check_parsers = sub_parsers.add_parser("check", parents=[argparser], help="检查域名")
    # subparsers.add_argument("-o", "--output", default="", help="报告文件名")
    check_parsers.add_argument(
        "-u", "--enumerate-users", action="store_true", default=False, help="枚举用户"
    )
    check_parsers.add_argument(
        "-s", "--summary", action="store_true", default=False, help="生成摘要"
    )
    check_parsers.set_defaults(func=handler_check)

    recon_parsers = sub_parsers.add_parser("recon", parents=[argparser], help="信息收集")
    recon_parsers.add_argument(
            "-b", "--banner", action="store_true", default=False, help="获取banner"
    )
    recon_parsers.add_argument(
            "-f", "--filename", help="输出文件名"
    )
    recon_parsers.set_defaults(func=handler_recon)


    args = argparser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        argparser.print_help()




if __name__ == "__main__":
    main()
