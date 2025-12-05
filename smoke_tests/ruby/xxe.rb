# XXE (XML External Entity) vulnerabilities in Ruby
require 'nokogiri'
require 'rexml/document'

class XxeController < ApplicationController
  # Test 1: Nokogiri with noent (entity substitution)
  def parse_nokogiri
    xml = params[:xml]
    # VULNERABLE: NOENT enables entity substitution
    doc = Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
    render plain: doc.to_xml
  end

  # Test 2: Nokogiri with DTDLOAD
  def parse_with_dtd
    xml = params[:xml]
    # VULNERABLE: Loading external DTD
    options = Nokogiri::XML::ParseOptions::DTDLOAD | Nokogiri::XML::ParseOptions::NOENT
    doc = Nokogiri::XML(xml, nil, nil, options)
    render plain: doc.to_xml
  end

  # Test 3: REXML with default settings
  def parse_rexml
    xml = params[:xml]
    # VULNERABLE: REXML expands entities by default in older versions
    doc = REXML::Document.new(xml)
    render plain: doc.to_s
  end

  # Test 4: Nokogiri with network access
  def parse_network
    xml = params[:xml]
    # VULNERABLE: DTDLOAD allows network access
    options = Nokogiri::XML::ParseOptions::DTDLOAD
    doc = Nokogiri::XML(xml, nil, nil, options)
    render plain: doc.root.text
  end

  # Test 5: XInclude processing
  def parse_xinclude
    xml = params[:xml]
    doc = Nokogiri::XML(xml)
    # VULNERABLE: XInclude can include external files
    doc.do_xinclude
    render plain: doc.to_xml
  end

  # Test 6: LibXML directly
  def parse_libxml
    xml = params[:xml]
    # VULNERABLE: Default options may enable external entities
    parser = LibXML::XML::Parser.string(xml)
    parser.context.options = LibXML::XML::Parser::Options::DTDLOAD
    doc = parser.parse
    render plain: doc.to_s
  end

  # Test 7: Ox parser
  def parse_ox
    xml = params[:xml]
    # Note: Ox doesn't expand external entities by default
    # but including for completeness
    doc = Ox.parse(xml)
    render plain: doc.to_s
  end

  # Test 8: SOAP with XXE
  def parse_soap
    xml = request.raw_post
    # VULNERABLE: SOAP message with external entities
    doc = Nokogiri::XML(xml, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
    # Process SOAP...
    render plain: "Processed"
  end

  # Test 9: XML from file upload
  def upload_xml
    file = params[:file]
    # VULNERABLE: Parsing uploaded XML with entities
    doc = Nokogiri::XML(file.read, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
    render plain: doc.to_xml
  end

  # Test 10: Parameter entity processing
  def parse_parameter_entity
    xml = params[:xml]
    # VULNERABLE: Parameter entities can exfiltrate data
    options = Nokogiri::XML::ParseOptions::DTDLOAD |
              Nokogiri::XML::ParseOptions::NOENT |
              Nokogiri::XML::ParseOptions::DTDATTR
    doc = Nokogiri::XML(xml, nil, nil, options)
    render plain: doc.to_xml
  end
end
