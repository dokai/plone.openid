from AccessControl.SecurityInfo import ClassSecurityInfo
from Acquisition import aq_parent
from BTrees.OOBTree import OOBTree
from DateTime import DateTime
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from openid.consumer.consumer import Consumer
from openid.consumer.consumer import SUCCESS
from openid.extensions import ax
from openid.extensions import sreg
from openid.yadis.discover import DiscoveryFailure
from persistent.mapping import PersistentMapping
from plone.openid.interfaces import IOpenIdExtractionPlugin
from plone.openid.store import ZopeStore
from zExceptions import Redirect

import logging
import transaction

manage_addOpenIdPlugin = PageTemplateFile("../www/openidAdd", globals(), 
                __name__="manage_addOpenIdPlugin")

logger = logging.getLogger("PluggableAuthService")

def addOpenIdPlugin(self, id, title='', REQUEST=None):
    """Add a OpenID plugin to a Pluggable Authentication Service.
    """
    p=OpenIdPlugin(id, title)
    self._setObject(p.getId(), p)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect("%s/manage_workspace"
                "?manage_tabs_message=OpenID+plugin+added." %
                self.absolute_url())


class OpenIdPlugin(BasePlugin):
    """OpenID authentication plugin.
    """

    meta_type = "OpenID plugin"
    security = ClassSecurityInfo()
    
    sreg_enabled = False
    sreg_attributes = tuple()
    sreg_attributes_required = tuple()
    ax_enabled = False
    ax_attributes = tuple()
    ax_attributes_required = tuple()

    _properties = BasePlugin._properties + (
        dict(id='sreg_enabled', type='boolean', mode='w', label='Enable SReg', description='Enables the Simple Registration extension.'),
        dict(id='sreg_attributes', type='lines', mode='w', label='SReg attributes', description='List of Simple Registration attributes to request from the OpenID provider.'),
        dict(id='sreg_attributes_required', type='lines', mode='w', label='Required SReg attributes', description='List of Simple Registration attributes that are required. This should be a subset of "SReg attributes".'),
        dict(id='ax_enabled', type='boolean', mode='w', label='Enable AX', description='Enables the Attribute Exchange 1.0 extension.'),
        dict(id='ax_attributes', type='lines', mode='w', label='AX attributes', description='List of attributes to request from the OpenID provider given as <alias> <type_uri>.'),
        dict(id='ax_attributes_required', type='lines', mode='w', label='Required AX attributes', description='List of required AX attributes. The items may be referenced by either <alias> or <type_uri> and must be listed in "AX attributes".'),
    )

    def __init__(self, id, title=None):
        self._setId(id)
        self.title=title
        self.store=ZopeStore()
        self._attribute_store = OOBTree()


    def getTrustRoot(self):
        pas=self._getPAS()
        site=aq_parent(pas)
        return site.absolute_url()


    def getConsumer(self):
        session=self.REQUEST["SESSION"]
        return Consumer(session, self.store)


    def extractOpenIdServerResponse(self, request, creds):
        """Process incoming redirect from an OpenId server.

        The redirect is detected by looking for the openid.mode
        form parameters. If it is found the creds parameter is
        cleared and filled with the found credentials.
        """

        mode=request.form.get("openid.mode", None)
        if mode=="id_res":
            # id_res means 'positive assertion' in OpenID, more commonly
            # described as 'positive authentication'
            creds.clear()
            creds["openid.source"]="server"
            creds["janrain_nonce"]=request.form.get("janrain_nonce")
            for (field,value) in request.form.iteritems():
                if field.startswith("openid.") or field.startswith("openid1_"):
                    creds[field]=request.form[field]
        elif mode=="cancel":
            # cancel is a negative assertion in the OpenID protocol,
            # which means the user did not authorize correctly.
            pass

    # IOpenIdExtractionPlugin implementation
    def initiateChallenge(self, identity_url, return_to=None):
        consumer=self.getConsumer()
        try:
            auth_request=consumer.begin(identity_url)
        except DiscoveryFailure, e:
            logger.info("openid consumer discovery error for identity %s: %s",
                    identity_url, e[0])
            return
        except KeyError, e:
            logger.info("openid consumer error for identity %s: %s",
                    identity_url, e.why)
            pass

        if self.getProperty('sreg_enabled', False):
            # List of SReg attributes defined in the 1.0 specification
            sreg_allowed_attributes = set(sreg.data_fields.keys())
            # Set of attributes the site considers required
            sreg_required_attributes = sreg_allowed_attributes.intersection(set(self.getProperty('sreg_attributes_required')))
            
            sreg_attributes = set()
            for attr_def in self.getProperty('sreg_attributes'):
                alias, name = attr_def.split(None, 2)
                sreg_attributes.add(name)
            sreg_attributes = sreg_allowed_attributes.intersection(sreg_attributes)

            sreg_optional_attributes = sreg_attributes - sreg_required_attributes

            sreg_request = sreg.SRegRequest()
            sreg_request.requestFields(list(sreg_optional_attributes), required=False)
            sreg_request.requestFields(list(sreg_required_attributes), required=True)

            auth_request.addExtension(sreg_request)

        if self.getProperty('ax_enabled', False):
            ax_attributes_required = set(self.getProperty('ax_attributes_required'))
            ax_request = ax.FetchRequest()

            for attr_def in self.getProperty('ax_attributes'):
                alias, type_uri = attr_def.split(None, 2)
                required = alias in ax_attributes_required or type_uri in ax_attributes_required
                ax_request.add(ax.AttrInfo(type_uri, alias=alias, required=required))

            auth_request.addExtension(ax_request)

        if return_to is None:
            return_to=self.REQUEST.form.get("came_from", None)
        if not return_to or 'janrain_nonce' in return_to:
            # The conditional on janrain_nonce here is to handle the case where
            # the user logs in, logs out, and logs in again in succession.  We
            # were ending up with duplicate open ID variables on the second response
            # from the OpenID provider, which was breaking the second login.
            return_to=self.getTrustRoot()

        url=auth_request.redirectURL(self.getTrustRoot(), return_to)

        # There is evilness here: we can not use a normal RESPONSE.redirect
        # since further processing of the request will happily overwrite
        # our redirect. So instead we raise a Redirect exception, However
        # raising an exception aborts all transactions, which means our
        # session changes are not stored. So we do a commit ourselves to
        # get things working.
        # XXX this also f**ks up ZopeTestCase
        transaction.commit()
        raise Redirect, url


    # IExtractionPlugin implementation
    def extractCredentials(self, request):
        """This method performs the PAS credential extraction.

        It takes either the zope cookie and extracts openid credentials
        from it, or a redirect from an OpenID server.
        """
        creds={}
        identity=request.form.get("__ac_identity_url", None)
        if identity is not None and identity != "":
            self.initiateChallenge(identity)
            return creds
            
        self.extractOpenIdServerResponse(request, creds)
        return creds


    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):
        if not credentials.has_key("openid.source"):
            return None

        if credentials["openid.source"]=="server":
            consumer=self.getConsumer()
            
            # remove the extractor key that PAS adds to the credentials,
            # or python-openid will complain
            query = credentials.copy()
            del query['extractor']
            
            result=consumer.complete(query, self.REQUEST.ACTUAL_URL)
            identity=result.identity_url
            
            if result.status==SUCCESS:
                # Simple Registration properties
                if self.getProperty('sreg_enabled', False):
                    sreg_response = sreg.SRegResponse.fromSuccessResponse(result)
                    if sreg_response is not None:
                        if not hasattr(self, '_attribute_store'):
                            self._attribute_store = OOBTree()

                        sreg_attributes = dict(sreg_response)
                        user_attributes = {}
                        for attr_def in self.getProperty('sreg_attributes'):
                            alias, name = attr_def.split(None, 2)
                            user_attributes[alias] = sreg_attributes.get(name, '').decode('utf-8')
                            if name == 'dob':
                                # Parse the date-of-birth fields to a DateTime
                                try:
                                    user_attributes[alias] = DateTime(user_attributes[alias])
                                except:
                                    pass

                        if user_attributes:
                            self._attribute_store.setdefault(identity, PersistentMapping()).update(user_attributes)

                # Attribute Exchange properties
                if self.getProperty('ax_enabled', False):
                    ax_response = ax.FetchResponse.fromSuccessResponse(result)
                    if ax_response is not None:
                        if not hasattr(self, '_attribute_store'):
                            self._attribute_store = OOBTree()

                        user_attributes = {}
                        for attr_def in self.getProperty('ax_attributes'):
                            alias, type_uri = attr_def.split(None, 2)
                            if ax_response.count(type_uri) >= 1:
                                # We always take the first returned attribute
                                # value even if multiple are offered.
                                value = ax_response.get(type_uri)[0].decode('utf-8')
                            else:
                                value = u''

                            if value.strip():
                                # Only use non-empty values so we don't mask
                                # attributes that were possibly acquired
                                # through SReg.
                                user_attributes[alias] = value

                        if user_attributes:
                            self._attribute_store.setdefault(identity, PersistentMapping()).update(user_attributes)

                self._getPAS().updateCredentials(self.REQUEST,
                        self.REQUEST.RESPONSE, identity, "")
                return (identity, identity)
            else:
                logger.info("OpenId Authentication for %s failed: %s",
                                identity, result.message)

        return None


    # IUserEnumerationPlugin implementation
    def enumerateUsers(self, id=None, login=None, exact_match=False,
            sort_by=None, max_results=None, **kw):
        """Slightly evil enumerator.

        This is needed to be able to get PAS to return a user which it should
        be able to handle but who can not be enumerated.

        We do this by checking for the exact kind of call the PAS getUserById
        implementation makes
        """
        if id and login and id!=login:
            return None

        if (id and not exact_match) or kw:
            return None

        key=id and id or login

        if not (key.startswith("http:") or key.startswith("https:")):
            return None

        return [ {
                    "id" : key,
                    "login" : key,
                    "pluginid" : self.getId(),
                } ]


    def getPropertiesForUser(self, user, request=None):
        try:
            return self._attribute_store.get(user.getId(), {})
        except AttributeError:
            self._attribute_error = OOBTree()
            return {}

classImplements(OpenIdPlugin, IOpenIdExtractionPlugin, IAuthenticationPlugin,
                IUserEnumerationPlugin, IPropertiesPlugin)


