# LIAV-Checker (LLM-Integrated Application Vulnerability Checker)
## Description
LIAV-Checker is a security tool based on [Vulnhuntr](https://github.com/protectai/vulnhuntr), designed to detect and address vulnerabilities in LangChain-based LLM applications. With 18 predefined templates, it identifies risks like Indirect Prompt Injection, SQL Injection, and SSRF via prompt injection, ensuring robust security for AI-powered applications.

![image](https://github.com/user-attachments/assets/85e342ae-1da5-4c24-86f4-fced43ac2e17)

## Installation
```
conda create -n LIAV_Checker python=3.10 pip install -r requirments.txt
```

## Usage
```
export OPENAI_API_KEY=[Your_Key]
python3 __main__.py -r [Target_Project_Folder] -a [Target_File (option)]  -l gpt
