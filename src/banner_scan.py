#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pandas as pd
from spoofcheck import SpoofCheck
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_domain(sc, unit, domain):
    """扫描单个域名获取 banner 信息"""
    # 跳过中文域名和IP地址
    if any(ord(c) > 127 for c in domain) or domain.replace('.', '').isdigit():
        return {
            "unit": unit,
            "domain": domain,
            "banner": "",
            "brand": ""
        }
    
    try:
        brand, banner = sc.get_brand(domain)
        print(domain, brand, banner)
        return {
            "unit": unit,
            "domain": domain,
            "banner": banner,
            "brand": brand
        }
    except Exception as e:
        print(f"Error scanning {domain}: {str(e)}")
        return {
            "unit": unit,
            "domain": domain,
            "banner": "",
            "brand": ""
        }

def main():
    # 加载域名信息
    with open('result.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    sc = SpoofCheck()
    reports = []
    domains_to_scan = []
    
    # 首先处理失败的单位和收集需要扫描的域名
    for unit, items in data.items():
        if isinstance(items, str):  # 处理失败的单位
            reports.append({
                "unit": unit,
                "domain": "",
                "banner": "",
                "brand": ""
            })
        else:
            for item in items:
                if isinstance(item, dict) and 'domain' in item:
                    domains_to_scan.append((unit, item['domain']))
    
    # 使用线程池并发扫描域名
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {
            executor.submit(scan_domain, sc, unit, domain): (unit, domain)
            for unit, domain in domains_to_scan
        }
        
        for future in as_completed(future_to_domain):
            result = future.result()
            reports.append(result)
    
    if reports:
        pd.DataFrame(reports).to_csv('domain_banners.csv', index=False)
        print("结果已保存到: domain_banners.csv")
    else:
        print("没有找到有效的扫描结果")

if __name__ == '__main__':
    main()
