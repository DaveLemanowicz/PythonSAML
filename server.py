from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ElementTree, Element, SubElement, tostring
from jinja2 import Template
from base64 import b64encode
from uuid import uuid4
from flask import Flask,make_response
from datetime import datetime,timedelta
import dm.xmlsec.binding as xmlsec
from os.path import dirname, basename
from lxml.etree import tostring
import StringIO
app = Flask(__name__)

#This causes the server to reload
#when the code changes
app.config.update(
    DEBUG = True
)


post_template_str = '''
<body onload="document.getElementsByTagName('input')[0].click();">

    <noscript>
        <p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p> 
    </noscript> 
    
    <form method="post" action="{{ url }}">
    <!-- Need to add this element and call click method, because calling submit()
    on the form causes failed submission if the form has another element with name or id of submit.
    See: https://developer.mozilla.org/en/DOM/form.submit#Specification -->
    <input type="submit" style="display:none;" />
<input type="hidden" name="SAMLResponse" value="{{ SAML }}" />
        <noscript>
            <input type="submit" value="Submit" />
        </noscript>
    </form>
</body>
'''
xml_template_str = '''
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{response_id}}" Version="2.0" IssueInstant="{{issue_instant}}" Destination="{{ recipient_url }}">
  <saml:Issuer>{{issuer_url}}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{{assertion_id}}" Version="2.0" IssueInstant="{{issue_instant}}">
    <saml:Issuer>{{issuer_url}}</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="{{audience_url}}" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">6501040ce8c509bda2faccb7579de6c5aefddad8</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{{not_on_or_after}}" Recipient="{{ recipient_url }}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{{issue_instant}}" NotOnOrAfter="{{not_on_or_after}}">
      <saml:AudienceRestriction>
        <saml:Audience>{{audience_url}}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{{issue_instant}}" SessionNotOnOrAfter="{{session_not_on_or_after}}" SessionIndex="{{session_index}}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">{{federation_id}}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
'''

def saml_timestamp(seconds_in_future=0):
    dt = datetime.utcnow()
    dt += timedelta(seconds=seconds_in_future)
    dt_str = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:19]
    return dt_str + 'Z'

SAML_vars = {
    'response_id':uuid4(),
    'assertion_id':uuid4(),
    'session_index':uuid4(),
    'audience_url':'https://dl.my.salesforce.com',
    'recipient_url':'https://dl.my.salesforce.com?so=00Do0000000IuhJ',
    'issuer_url':'http://dev1.onshift.com:8989/sso',
    'issue_instant':saml_timestamp(),
    'not_on_or_after':saml_timestamp(600),
    'session_not_on_or_after':saml_timestamp(8*60*60),
    'federation_id':'test',
}


def sign_file(xml_file, root_id, key_file, cert_file):
    """sign *xml_file* with *key_file* and include content of *cert_file*.
    *xml_file* can be a file, a filename string or an HTTP/FTP url.

    *key_file* contains the PEM encoded private key. It must be a filename string.

    *cert_file* contains a PEM encoded certificate (corresponding to *key_file*),
    included as `X509Data` in the dynamically created `Signature` template.
    """
    # template aware infrastructure
    from dm.xmlsec.binding.tmpl import parse, Element, SubElement, \
         fromstring, XML
    from dm.xmlsec.binding.tmpl import Signature

    doc = parse(xml_file)

    # Sign the assertion
    import pdb; pdb.set_trace()
    assertion = doc.findall('saml:Assertion', {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"})[0]
    signature = Signature(xmlsec.TransformExclC14N, xmlsec.TransformRsaSha1)
    assertion.insert(0, signature)
    ref = signature.addReference(xmlsec.TransformSha1)
    ref.addTransform(xmlsec.TransformEnveloped)
    key_info = signature.ensureKeyInfo()
    key_info.addKeyName()
    key_info.addX509Data()
    dsigCtx = xmlsec.DSigCtx()
    signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
    signKey.loadCert(cert_file, xmlsec.KeyDataFormatPem)
    dsigCtx.signKey = signKey
    dsigCtx.sign(signature)

    # Sign the whole document
    signature = Signature(xmlsec.TransformExclC14N, xmlsec.TransformRsaSha1)
    doc.getroot().insert(0, signature)
    ref = signature.addReference(xmlsec.TransformSha1)
    #ref.attrib['URI'] = root_id
    ref.addTransform(xmlsec.TransformEnveloped)
    key_info = signature.ensureKeyInfo()
    key_info.addKeyName()
    key_info.addX509Data()
    dsigCtx = xmlsec.DSigCtx()
    signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
    signKey.loadCert(cert_file, xmlsec.KeyDataFormatPem)
    dsigCtx.signKey = signKey
    dsigCtx.sign(signature)
    return tostring(doc)

@app.route('/sso', methods=['GET', 'POST'])
def sso(*args, **kwargs):
    print
    print '===========================> in sso'
    print
    xml_template = Template(xml_template_str)
    saml_xml = xml_template.render(SAML_vars)
    print 'start SAML xml ================================'
    print saml_xml
    print 'end SAML xml ========================================='
    key_root = "/Users/willmooney/projects/"
    signed_saml_xml = sign_file(StringIO.StringIO(saml_xml), str(SAML_vars['response_id']),
            '{0}PythonSAML/test.pem'.format(key_root),
            '{0}PythonSAML/test.crt'.format(key_root))
    print 'start signed SAML xml ================================'
    print signed_saml_xml
    print 'end signed DSAML xml ================================================'
    post_template = Template(post_template_str)
    template_vars = {
      'url':'https://dl.my.salesforce.com/?so=00Do0000000IuhJ',
      'SAML':b64encode(saml_xml),
    }
    response = make_response(post_template.render(template_vars))
    return response


#
# Default handler for paths not otherwise defined
#
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    print
    print '===========================> You want path: %s' % path
    print
    return 'You want path: %s' % path

if __name__ == '__main__':
    xmlsec.initialize()
    app.run()
