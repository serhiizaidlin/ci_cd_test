import json
import subprocess
import os 
import sys 
from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

def semgrep_scan(report_path: str):
    """
    Run semgrep scan and output results to json file
    :param report_path: output file path
    """
    command = f'semgrep -c p/security-audit --max-target-bytes 10000000 -o {report_path} --json'
    try:
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        return output
    except Exception as e:
        print(f'[ERROR] Failed to execute bash command: {command}')
        print(f'Error: {e}')
        sys.exit(1)

def detect_secrets():
    """
    Run detect-secrets scan and return results as json
    """
    command = f'detect-secrets scan --all-files'
    try:
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        output_json = json.loads(output)
    except Exception as e:
        print(f'[ERROR] Failed to execute bash command: {command}')
        print(f'Error: {e}')
        sys.exit(1)
    return output_json

def convert_semgrep(report_path: str):
    """
    Convert data from semgrep json to unified format
    :param application: git repository name that is scanned with a SAST tool
    :param report_data: scanner output
    """
    print("\nProcessing semgrep report")
    report_data = json.load(open(report_path, "r"))
    
    try:
        semgrep_data = report_data['results']

    except KeyError as e:
        print(f'Failed to load file scan result from Semgrep file.')
        print(f'Error: {e}')
        sys.exit(1)

    final_report = {"findings": []}

    if not semgrep_data:
        # if there is no finding return empty dict.
        return final_report

    for vuln_record in semgrep_data:
        # Vulnerability record metadata
        finding = dict()
        finding['language'] = vuln_record['check_id'].split(".")[0].capitalize()
        finding['scan_tool'] = 'Semgrep'
        finding['name'] = vuln_record['check_id']
        finding['source_file'] = vuln_record["path"]
        finding['source_line'] = vuln_record['start']['line']
        finding['code_snippet'] = vuln_record["extra"]["lines"]
        finding['description'] = vuln_record["extra"]["message"]
        finding['severity'] = vuln_record["extra"]["severity"]
        final_report['findings'].append(finding)

    return final_report

def convert_secrets(scan_results: str):
    """
    Convert data from detect-secrets json to unified format
    """
    print("\nProcessing detect-secrets report")
      
    final_report = {"findings": []}
    secrets_data = scan_results['results']
    if not secrets_data:
        # if there is no finding return empty dict.
        return final_report

    for vuln_record in secrets_data:
        # Vulnerability record metadata
        finding = dict()
        for item in secrets_data[vuln_record]:
            finding['language'] = 'Generic'
            finding['scan_tool'] = 'detect-secrets'
            finding['name'] = item['type']
            finding['source_file'] = item['filename']
            finding['source_line'] = item['line_number']
            finding['description'] = f"Possible {item['type']} found"
            finding['severity'] = 'HIGH'
            final_report['findings'].append(finding)

    return final_report

def find_max_key_size(finding: dict) -> int:
    """
    Find max length of key in finding
    :param finding: current finding
    :return: length of max key
    """
    max_len = 0

    for key in finding.keys():
        if len(key) > max_len:
            max_len = len(key)

    return max_len


def print_findings_to_stdout(findings: dict, tool_name: str):
    """
    Print findings details to stdout
    :param findings: dictionary with all findings
    :param tool_name: scanner name
    :param tool_name: findings count
    """
    count = 0
    if findings:
        # print(f'\n{tool_name.capitalize()} Vulnerabilities Details:')
        for finding in findings:
            print(f"\n[{finding['severity']}] severity vulnerability found:")
            # Format output with padding
            max_len = find_max_key_size(finding)
            for key, value in finding.items():
                if isinstance(value, str):
                    value = value.replace("\n", " \\n ")
                padding = max_len - len(key)
                value = ' ' * padding + '"' + str(value) + '",'
                print(f'\t"{key}": {value}')
            count += 1
    if count == 0:
        print(f'\nNo vulnerabilities were found.')
    return count

if __name__ == "__main__":

    github_account = 'https://github.com/serhiizaidlin/'
    repo_name = 'sample-nodejs'

    #Check if repository already exeists locally and clone it from github if not
    print(f"\n[!] --------------------------- PIPELINE START ----------------------------- [!]")
    print(f"\n[!] ---------------------------- CHECKOUT SCM ------------------------------ [!]")
    if os.path.isdir(repo_name):
        os.chdir(repo_name)
        print("Local repository already exists")
    else:
        subprocess.check_output(['git', 'clone', f'{github_account}{repo_name}'])
        os.chdir(repo_name)
    CWD = os.getcwd()
    print(f'Current Working Directory = {CWD}')

    #Run security Checks
    print(f"\n[!] --------------------- SECURITY STAGE DETAILS BEGIN --------------------- [!]")
    #Running semgrep scan
    print (f'\n[INFO] Starting `semgrep` scan')
    semgrep_output = '/tmp/reports/semgrep_findings.json'
    semgrep_scan(semgrep_output)
    print (f'\n[INFO] Completed `semgrep` scan')

    #Running detect-secrets scan
    print (f'\n[INFO] Starting `detect-secrets` scan')
    detect_secrets_results = detect_secrets()
    print (f'\n[INFO] Completed `detect-secrets` scan')


    #Processing scan results
    print(f"\n[!] ---------------------- PROCESS SCAN RESULTS START ---------------------- [!]")
    results={}
    results['semgrep'] = convert_semgrep(semgrep_output)
    results['secrets'] = convert_secrets(detect_secrets_results)
    findings_counter = 0
    for tool in results:
        if tool == 'semgrep':
            print("\n[!] --------------------- SEMGREP --------------------- [!]")
        elif tool == 'secrets':
            print("\n[!] --------------------- SECRETS --------------------- [!]")
        count = print_findings_to_stdout(results[tool]['findings'], tool)
        findings_counter+=count
    print(f"\n[!] ----------------------- PROCESS SCAN RESULTS END ----------------------- [!]")
    if findings_counter != 0:
        print(f"\n[!] ---------------------------- BUILD FAILED ------------------------------ [!]")
        print(f"\nBuild failed due to security issues found in a source code. Please fix all findings and restart the pipeline")
    else:
        #Build app image
        print(f"\n[!] ----------------------------- IMAGE BUILD ------------------------------ [!]")
        #Check if previous version of app is already running
        output = subprocess.check_output(['docker', 'ps'])
        output_lines = output.decode().split('\n')
        image_running = False
        for line in output_lines:
            if repo_name in line:
                image_running = True
                image_id = line.split()[0]
        if image_running:
            # print(image_id)
            print (f'\n[INFO] Stopping old docker container')
            stop_command = f'docker stop {image_id}'
            rm_command = f'docker rm {image_id}'
            subprocess.check_output(stop_command.split())
            subprocess.check_output(rm_command.split())
        subprocess.check_output(['docker', 'build', '-t', repo_name, '.'])
        print (f'\n[INFO] Image `{repo_name}` built successfully')

        #Run application
        print(f"\n[!] --------------------------- RUN APPLICATION ---------------------------- [!]")
        print (f'\n[INFO] Starting docker container')    
        run_command = f'docker run -p 3333:3000 {repo_name}'
        subprocess.Popen(run_command.split())
        print (f'\n[INFO] Started docker container')
        print (f'\n App is running: http://localhost:3333')
    print(f"\n[!] ---------------------------- PIPELINE END ------------------------------ [!]")