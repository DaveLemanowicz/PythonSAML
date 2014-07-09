from xml.etree.ElementTree import ElementTree, Element, SubElement, tostring
from flask import Flask,redirect
app = Flask(__name__)

#This causes the server to reload
#when the code changes
app.config.update(
    DEBUG = True
)


@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/sso', methods=['GET', 'POST'])
def sso(*args, **kwargs):
    print
    print '===========================> in sso'
    print 

    top = Element('{http://dave-l.org}Response')
    Issuer = SubElement(top,'{http://example.com}Issuer')

    print tostring(top)

    return redirect("https://dl.my.salesforce.com/?so=00Do0000000IuhJ")



    return 'in sso'

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
    app.run('172.22.1.55',8989)
