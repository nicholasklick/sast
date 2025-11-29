from flask import Flask, request
import lxml.etree as ET

app = Flask(__name__)

# Malicious XML payload an attacker might send
# This attempts to read /etc/passwd from the server
xxe_payload = """
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
"""

@app.route('/process-xml', methods=['POST'])
def process_xml():
    # Get XML from the request
    xml_data = request.data

    # --- VULNERABLE CODE ---
    # Parsing XML without disabling DTDs (Document Type Definitions)
    # By default, lxml disables this, so we explicitly enable it to show the vulnerability
    parser = ET.XMLParser(resolve_entities=True)
    tree = ET.fromstring(xml_data, parser) # CWE-611: Improper Restriction of XML External Entity Reference
    # -----------------------

    # Process the XML (here, just printing it)
    result = ET.tostring(tree)
    return result

if __name__ == '__main__':
    # To test: curl -X POST -d@xxe_payload.xml http://127.0.0.1:5000/process-xml
    # where xxe_payload.xml contains the payload above.
    # This is a simplified example; in a real app, the XML would come from a user.
    print("This is a Flask app demonstrating XXE. Not meant to be run directly in tests.")
