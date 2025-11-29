
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # Vulnerable to XXE
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser)
    return etree.tostring(tree)

if __name__ == '__main__':
    app.run()
