// 列配置
const COLUMN_CONFIGS = {
  check_time: { label: "检查时间", class: "min-w-[160px]" },
  host: { label: "域名", class: "min-w-[120px]" },
  risk_level: { label: "风险等级", class: "min-w-[100px]" },
  risk_name: { label: "风险名称", class: "min-w-[200px]" },
  risk_category: { label: "风险类别", class: "min-w-[100px]" },
  description: { label: "描述", class: "min-w-[300px]" },
  envidance: { label: "证据", class: "min-w-[200px]" },
  fix_advice: { label: "修复建议", class: "min-w-[200px]" }
};

// 风险等级样式映射
function getRiskLevelClass(level) {
  const levelMap = {
    "高风险": "text-dracula-red font-semibold bg-dracula-red/20 px-2 py-1 rounded",
    "中风险": "text-dracula-orange font-semibold bg-dracula-orange/20 px-2 py-1 rounded",
    "低风险": "text-dracula-green font-semibold bg-dracula-green/20 px-2 py-1 rounded",
    "安全": "text-dracula-green font-semibold bg-dracula-green/20 px-2 py-1 rounded"
  };
  return levelMap[level] || "";
}

// 创建表头
function createTableHeader() {
  const headerRow = document.createElement("tr");
  Object.values(COLUMN_CONFIGS).forEach(({ label }) => {
    const th = document.createElement("th");
    th.className = "px-4 py-3 text-left text-sm font-semibold text-dracula-purple";
    th.textContent = label;
    headerRow.appendChild(th);
  });
  return headerRow;
}

// 创建风险行
function createRiskRow(riskData) {
  const row = document.createElement("tr");
  row.className = "hover:bg-dracula-selection transition-colors duration-200";

  Object.keys(COLUMN_CONFIGS).forEach((key) => {
    const td = document.createElement("td");
    td.className = "px-4 py-3 text-sm whitespace-pre-wrap";
    
    // 获取实际的值（从对象的第一个键值对中获取值）
    const value = riskData[key] ? riskData[key]["0"] || "" : "";
    
    if (key === "risk_level") {
      td.className += " " + getRiskLevelClass(value);
    }
    
    td.textContent = value;
    row.appendChild(td);
  });

  return row;
}

// 检查域名
function checkDomain() {
  const domainInput = document.getElementById("domainInput");
  const checkButton = document.getElementById("checkButton");
  const loading = document.getElementById("loading");
  const error = document.getElementById("error");
  const tableContainer = document.getElementById("tableContainer");
  const tableHead = document.getElementById("tableHead");
  const tableBody = document.getElementById("tableBody");

  // 重置状态
  error.classList.add("hidden");
  tableContainer.classList.add("hidden");
  loading.classList.remove("hidden");
  domainInput.disabled = true;
  checkButton.disabled = true;

  // 检查域名是否为空
  if (!domainInput.value.trim()) {
    Swal.fire({
      title: '错误',
      text: '请输入域名',
      icon: 'error',
      confirmButtonText: '确定',
      showClass: {
        popup: 'animate__animated animate__fadeIn'
      },
      hideClass: {
        popup: 'animate__animated animate__fadeOut'
      }
    });
    loading.classList.add("hidden");
    domainInput.disabled = false;
    checkButton.disabled = false;
    return;
  }

  fetch("/check", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ domain: domainInput.value.trim() }),
  })
    .then(async (response) => {
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error);
      }
      return data;
    })
    .then((data) => {
      loading.classList.add("hidden");
      domainInput.disabled = false;
      checkButton.disabled = false;

      // 清空之前的结果
      tableBody.innerHTML = "";
      tableHead.innerHTML = "";

      if (data.info) {
        // 处理无风险情况
        const headerRow = document.createElement("tr");
        const th = document.createElement("th");
        th.className = "px-4 py-3 text-left text-sm font-semibold text-dracula-purple";
        th.textContent = "检查结果";
        headerRow.appendChild(th);
        tableHead.appendChild(headerRow);

        const row = document.createElement("tr");
        row.className = "hover:bg-dracula-selection transition-colors duration-200";
        const td = document.createElement("td");
        td.className = "px-4 py-3 text-sm whitespace-pre-wrap " + getRiskLevelClass("安全");
        td.textContent = data.info;
        row.appendChild(td);
        tableBody.appendChild(row);
      } else {
        // 处理有风险情况
        tableHead.appendChild(createTableHeader());
        const row = createRiskRow(data);
        tableBody.appendChild(row);
      }

      tableContainer.classList.remove("hidden");
    })
    .catch((error) => {
      console.error("Error:", error);
      loading.classList.add("hidden");
      domainInput.disabled = false;
      checkButton.disabled = false;
      
      // 使用 SweetAlert2 显示错误信息
      Swal.fire({
        title: '错误',
        text: error.message,
        icon: 'error',
        confirmButtonText: '确定',
        showClass: {
          popup: 'animate__animated animate__fadeIn'
        },
        hideClass: {
          popup: 'animate__animated animate__fadeOut'
        }
      });
    });
}

// 初始化事件监听器
document.addEventListener("DOMContentLoaded", function() {
  // 添加回车键支持
  document.getElementById("domainInput").addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
      event.preventDefault();
      checkDomain();
    }
  });

  // 添加按钮点击事件
  document.getElementById("checkButton").addEventListener("click", checkDomain);
});
