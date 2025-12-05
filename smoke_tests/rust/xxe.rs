// XXE (XML External Entity) Test Cases

// Test 1: XML parsing with external entities enabled
fn parse_xml_with_entities(xml_str: &str) -> Result<roxmltree::Document, roxmltree::Error> {
    // VULNERABLE: roxmltree doesn't expand entities by default, but simulating vulnerability
    roxmltree::Document::parse(xml_str)
}

// Test 2: Quick-xml parsing without security
fn parse_xml_quick(xml_bytes: &[u8]) -> Result<(), quick_xml::Error> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(xml_bytes);
    reader.trim_text(true);

    loop {
        // VULNERABLE: Processing XML without entity restrictions
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Err(e) => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

// Test 3: Serde XML deserialization
fn deserialize_xml<T: serde::de::DeserializeOwned>(xml_str: &str) -> Result<T, quick_xml::DeError> {
    // VULNERABLE: Deserializing XML without entity protection
    quick_xml::de::from_str(xml_str)
}

// Test 4: XML-rs parser
fn parse_with_xmlrs(xml_str: &str) -> Result<(), xml::reader::Error> {
    use xml::reader::{EventReader, XmlEvent};

    let parser = EventReader::from_str(xml_str);
    // VULNERABLE: No explicit entity restrictions
    for event in parser {
        match event? {
            XmlEvent::EndDocument => break,
            _ => {}
        }
    }
    Ok(())
}

// Test 5: Minidom XML parsing
fn parse_minidom(xml_str: &str) -> Result<minidom::Element, minidom::Error> {
    // VULNERABLE: Parsing untrusted XML
    xml_str.parse::<minidom::Element>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xxe() {
        let xml = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
        let _ = parse_xml_with_entities(xml);
    }
}
