from AccessControl.SecurityInfo import ClassSecurityInfo
from Acquisition import aq_parent
from BTrees.OOBTree import OOBTree
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
from plone.openid.interfaces import IOpenIdExtractionPlugin
from plone.openid.store import ZopeStore
from zExceptions import Redirect

import logging
import transaction
import urlparse

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

    provider_blacklist = tuple()
    provider_whitelist = tuple()
    sreg_enabled = False
    sreg_attributes = tuple()
    sreg_attributes_required = tuple()
    ax_enabled = False
    ax_attributes = tuple()
    ax_attributes_required = tuple()
    strict_required_attributes = False

    _properties = BasePlugin._properties + (
        dict(id='provider_blacklist', type='lines', mode='w', label='Provider blacklist', description='List of provider domains that are not accepted for authentication. Other domains will be accepted.'),
        dict(id='provider_whitelist', type='lines', mode='w', label='Provider whitelist', description='List of provider domains that are accepted for authentication. Other domains will be declined.'),
        dict(id='strict_required_attributes', type='boolean', mode='w', label='Strict required attributes', description='If True, authentication will be declined if required attributes are missing.'),
        dict(id='sreg_enabled', type='boolean', mode='w', label='Enable SReg', description='Enables the Simple Registration extension.'),
        dict(id='sreg_attributes', type='lines', mode='w', label='SReg attributes', description='List of Simple Registration attributes to request from the OpenID provider given as "<alias> <attr_name>" tokens, one per line.'),
        dict(id='sreg_attributes_required', type='lines', mode='w', label='Required SReg attributes', description='List of required Simple Registration attributes. The items may be referenced by either <alias> or <attr_name> and must be listed in "SReg attributes".'),
        dict(id='ax_enabled', type='boolean', mode='w', label='Enable AX', description='Enables the Attribute Exchange 1.0 extension.'),
        dict(id='ax_attributes', type='lines', mode='w', label='AX attributes', description='List of attributes to request from the OpenID provider given as "<alias> <type_uri>" tokens, one per line.'),
        dict(id='ax_attributes_required', type='lines', mode='w', label='Required AX attributes', description='List of required AX attributes. The items may be referenced by either <alias> or <type_uri> and must be listed in "AX attributes".'),
    )

    def __init__(self, id, title=None):
        self._setId(id)
        self.title=title
        self.store=ZopeStore()
        self._attribute_store = OOBTree()

    def clearAttributes(self, identity=None):
        """Empties the attribute store."""
        if identity is None:
            self._attribute_store.clear()
        else:
            self._attribute_store.pop(identity, None)

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

    def getSRegAttributeInfo(self):
        """Returns a set of (attr_name, alias, required) tuples of the
        configured Simple Registration attributes.
        """
        # Set of SReg attributes defined in the 1.1 specification
        sreg_allowed_attributes = set(sreg.data_fields.keys())

        # Set of valid SReg attributes the site considers required
        sreg_required_attributes = sreg_allowed_attributes.intersection(
            set(self.getProperty('sreg_attributes_required')))

        sreg_attributes = set()
        for attr_def in self.getProperty('sreg_attributes'):
            alias, name = attr_def.split(None, 2)
            if name in sreg_allowed_attributes:
                sreg_attributes.add((name, alias, name in sreg_required_attributes))

        return sreg_attributes


    def getAXAttributeInfo(self):
        """Returns a list of (type_uri, alias, required) tuples of the
        configured Attribute Exchanged attributes.
        """
        ax_attributes_required = set(self.getProperty('ax_attributes_required'))

        ax_attributes = set()
        for attr_def in self.getProperty('ax_attributes'):
            alias, type_uri = attr_def.split(None, 2)
            required = alias in ax_attributes_required or type_uri in ax_attributes_required
            ax_attributes.add((type_uri, alias, required))

        return ax_attributes

    def allowProvider(self, identity_url):
        """Returns True if the OpenID provider referenced by ``identity_url``
        should be allowed to provide authentication, False otherwise.
        """
        if identity_url is None:
            return False

        allow_provider = True
        if not (identity_url.startswith('http://') or identity_url.startswith('https://')):
            identity_url = 'http://%s' % identity_url

        identity_domain = urlparse.urlparse(identity_url).netloc

        blacklist = set(self.getProperty('provider_blacklist', []))
        if len(blacklist) > 0:
            for provider in blacklist:
                provider_domain = urlparse.urlparse(provider).netloc
                if provider_domain in identity_domain:
                    allow_provider = False
                    break

        whitelist = set(self.getProperty('provider_whitelist', []))
        if len(whitelist) > 0:
            allow_provider = False
            for provider in whitelist:
                provider_domain = urlparse.urlparse(provider).netloc
                if provider_domain in identity_domain:
                    allow_provider = True
                    break

        return allow_provider

    # IOpenIdExtractionPlugin implementation
    def initiateChallenge(self, identity_url, return_to=None):
        # Check the identity_url against the whilelist/blacklist policy
        if not self.allowProvider(identity_url):
            logger.info("openid provider blocked due to local policy: %s",
                    identity_url)
            return

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

        # Activate Simple Registration extension
        if self.getProperty('sreg_enabled', False):
            sreg_attributes = self.getSRegAttributeInfo()
            if len(sreg_attributes) > 0:
                sreg_request = sreg.SRegRequest()
                sreg_request.requestFields([name for (name, alias, required) in sreg_attributes if not required], required=False)
                sreg_request.requestFields([name for (name, alias, required) in sreg_attributes if required], required=True)

                auth_request.addExtension(sreg_request)

        # Activate Attribute Exchange extension
        if self.getProperty('ax_enabled', False):
            ax_attributes = self.getAXAttributeInfo()
            if len(ax_attributes) > 0:
                ax_request = ax.FetchRequest()

                for type_uri, alias, required in self.getAXAttributeInfo():
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
            
            if not self.allowProvider(identity):
                logger.info("OpenId Authentication for %s failed because the provider is not allowed.",
                    identity)
            elif result.status==SUCCESS:

                missing_attributes = set()
                user_attributes = self._attribute_store.get(identity, {})
                # Simple Registration properties
                if self.getProperty('sreg_enabled', False):
                    sreg_response = sreg.SRegResponse.fromSuccessResponse(result)
                    if sreg_response is not None:
                        if not hasattr(self, '_attribute_store'):
                            self._attribute_store = OOBTree()

                        sreg_attributes = dict(sreg_response)

                        for name, alias, required in self.getSRegAttributeInfo():
                            value = sreg_attributes.get(name, '').decode('utf-8').strip()
                            if value:
                                user_attributes[alias] = value
                            elif required:
                                missing_attributes.add((name, alias))

                        self._attribute_store[identity] = user_attributes

                # Attribute Exchange properties
                if self.getProperty('ax_enabled', False):
                    ax_response = ax.FetchResponse.fromSuccessResponse(result)
                    if ax_response is not None:
                        if not hasattr(self, '_attribute_store'):
                            self._attribute_store = OOBTree()

                        for type_uri, alias, required in self.getAXAttributeInfo():
                            try:
                                if ax_response.count(type_uri) >= 1:
                                    # We always take the first returned attribute
                                    # value even if multiple are offered.
                                    value = ax_response.get(type_uri)[0].decode('utf-8').strip()
                                else:
                                    value = u''
                            except KeyError:
                                # The AX specification allows the provider to
                                # either omit an attribute from the response
                                # (recommended) or explicitly return a count
                                # of zero items. For omitted attributes the
                                # openid library will raise a KeyError.
                                value = u''

                            if value.strip():
                                # Only use non-empty values so we don't mask
                                # attributes that were possibly acquired
                                # through SReg.
                                user_attributes[alias] = value

                            if required and len(user_attributes.get(alias, '').strip()) == 0:
                                missing_attributes.add((type_uri, alias))

                        values = self._attribute_store.get(identity, {})
                        values.update(user_attributes)
                        self._attribute_store[identity] = values

                if len(missing_attributes) > 0:
                    logger.info("Failed to receive required attributes for %s: %s",
                        identity, ", ".join("%s (%s)" % (alias, name) for name, alias in missing_attributes))

                    if self.getProperty('strict_required_attributes', False):
                        logger.info("OpenId Authentication for %s failed because of strict required parameters.",
                                identity)
                        # Clear the previous state of user attributes because
                        # in strict mode we consider this a fatal error and
                        # any existing user attributes invalid.
                        self.clearAttributes(identity)
                        return None

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
            self._attribute_store = OOBTree()
            return {}

classImplements(OpenIdPlugin, IOpenIdExtractionPlugin, IAuthenticationPlugin,
                IUserEnumerationPlugin, IPropertiesPlugin)
