## 📁 Note on Folder Structure

> ⚠️ This project is organized for better readability and understanding.

In a typical **SOC lab setup**, the **TheHive** component is logically part of the `WAZUH-UBUNTU-END` environment, as it integrates with Wazuh for alerting and incident response. However, in this repository, the `THEHIVE` folder is placed **outside** of `WAZUH-UBUNTU-END`.

### 💡 Reason
This structure is intentionally designed to:
- Improve repository readability 📖  
- Separate core components clearly 🧩  
- Make navigation easier for learners 🔍  

### 🏗️ Logical Lab Structure
WAZUH-UBUNTU-END/
├── >Wazuh (SIEM)
├── >Elasticsearch / Kibana
└── >TheHive (Incident Response)

### 📂 Repository Structure
SOC-LAB/
├── >WAZUH-UBUNTU-END/
└── >THEHIVE/

### ✅ Summary
Although separated in the repository, **TheHive should be considered part of the same SOC lab environment as Wazuh**, working together for monitoring and incident response.
