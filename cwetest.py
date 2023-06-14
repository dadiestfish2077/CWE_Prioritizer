import csv
import xml.etree.ElementTree as ET

data = []
with open('CWE_LIST.csv', mode='w', newline='') as csv_file:
    fieldnames = ['CWE ID', 'Name', 'Description', 'Scope' , 'Impact']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    file = 'cwec_v4.11.xml'

    tree = ET.parse(file)
    root = tree.getroot()
    for child in root.iter('{http://cwe.mitre.org/cwe-6}Weakness'):
        CWE_ID = child.get('ID')
        CWE_Name = child.get('Name')
        CWE_description = child.find('{http://cwe.mitre.org/cwe-6}Description')
        CWE_description_text = CWE_description.text
        Common_Consequences = child.find('.//{http://cwe.mitre.org/cwe-6}Common_Consequences')
        scopes = []
        impacts = []
        if Common_Consequences is not None:
            for consequence in Common_Consequences.findall('.//{http://cwe.mitre.org/cwe-6}Consequence'):
                for scope in consequence.findall('.//{http://cwe.mitre.org/cwe-6}Scope'):
                    scopes.append(scope.text)
                for impact in consequence.findall('.//{http://cwe.mitre.org/cwe-6}Impact'):
                    impacts.append(impact.text)
        scope_text = ', '.join(scopes)
        impact_text = ', '.join(impacts)
        data.append([CWE_ID, CWE_Name, CWE_description_text, scope_text])
        writer.writerow({'CWE ID': CWE_ID, 'Name': CWE_Name, 'Description': CWE_description_text, 'Scope': scope_text, 'Impact': impact_text})

