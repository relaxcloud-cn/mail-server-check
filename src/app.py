import re

from flask import Flask, jsonify, render_template, request
from loguru import logger

import spoofcheck

app = Flask(__name__, static_folder='static')


def is_valid_domain(domain):
    # 使用正则表达式校验域名格式
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"  # 第一部分：字母或数字
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"  # 中间部分：字母、数字或连字符
        r"+[a-zA-Z]{2,6}$"  # 顶级域名部分：2到6个字母
    )
    return pattern.match(domain) is not None


@app.route("/check", methods=["POST"])
def check_domain():
    data = request.get_json()
    domain = data.get("domain")
    # 校验域名格式
    if not is_valid_domain(domain):
        return jsonify({"error": "Invalid domain format"}), 400

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    checker = spoofcheck.SpoofCheck()
    report = checker.check(domain)
    if report is None:
        return jsonify({"info": "域名无风险"}), 200
    return jsonify(report.to_dict())


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
