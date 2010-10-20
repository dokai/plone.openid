import unittest
from zExceptions import Redirect

class TestOpenIdExtraction(unittest.TestCase):
    identity = "http://plone.myopenid.com"
    server_response={
            "openid.mode"              : "id_res",
            "nonce"                    : "nonce",
            "openid.identity"          : "http://plone.myopenid.com",
            "openid.assoc_handle"      : "assoc_handle",
            "openid.return_to"         : "return_to",
            "openid.signed"            : "signed",
            "openid.sig"               : "sig",
            "openid.invalidate_handle" : "invalidate_handle",
            }

    def createPlugin(self):
        from plone.openid.tests.utils import MockPAS
        from plone.openid.tests.utils import MockSite
        from plone.openid.plugins.oid import OpenIdPlugin
        plugin=OpenIdPlugin("openid")
        return plugin.__of__((MockPAS()).__of__(MockSite()))


    def testEmptyExtraction(self):
        """Test if we do not invent credentials out of thin air.
        """
        plugin=self.createPlugin()
        creds=plugin.extractCredentials(plugin.REQUEST)
        self.assertEqual(creds, {})


    def testEmptyStringIdentityExtraction(self):
        """Test coverage for bug #7176. In the case where "" (i.e an empty
           string) is passed in as the identity via the request, 
           we essentially want to ensure that a Redirect isn"t raised, which 
           would signify that an IOpenIdExtractionPlugin challenge was initialized.
           
           This test demonstrates our openid plugin"s extractCredentials eliminates
           credentials that aren"t in the openid.* namespace.
        """
        plugin=self.createPlugin()
        plugin.REQUEST.form.update(self.server_response)
        plugin.REQUEST.form["__ac_identity_url"]=""
        creds=plugin.extractCredentials(plugin.REQUEST)
        self.failIf(creds.has_key("__ac_identity_url"))
        

    def testRedirect(self):
        """Test if a redirect is generated for a login attempt.
        This test requires a working internet connection!
        """
        plugin=self.createPlugin()
        plugin.REQUEST.form["__ac_identity_url"]=self.identity
        self.assertRaises(Redirect,
                plugin.extractCredentials,
                plugin.REQUEST)


    def testPositiveOpenIdResponse(self):
        """Test if a positive authentication is extracted.
        """
        plugin=self.createPlugin()
        plugin.REQUEST.form.update(self.server_response)
        creds=plugin.extractCredentials(plugin.REQUEST)
        self.assertEqual(creds["openid.identity"], self.identity)
        self.assertEqual(creds["openid.mode"], "id_res")
        self.assertEqual(creds["openid.return_to"], "return_to")


    def testNegativeOpenIdResponse(self):
        """Check if a cancelled authentication request is correctly ignored.
        """
        plugin=self.createPlugin()
        plugin.REQUEST.form.update(self.server_response)
        plugin.REQUEST.form["openid.mode"]="cancel"
        creds=plugin.extractCredentials(plugin.REQUEST)
        self.assertEqual(creds, {})


    def testFormRedirectPriorities(self):
        """Check if a new login identity has preference over openid server
        response.
        """
        plugin=self.createPlugin()
        plugin.REQUEST.form.update(self.server_response)
        plugin.REQUEST.form["__ac_identity_url"]=self.identity
        self.assertRaises(Redirect,
                plugin.extractCredentials, plugin.REQUEST)

    def testAllowProvider_default_policy(self):
        """Check that all providers are allowed by default."""
        plugin=self.createPlugin()
        self.assertEquals(plugin.getProperty("provider_blacklist"), tuple())
        self.assertEquals(plugin.getProperty("provider_whitelist"), tuple())

        self.failUnless(plugin.allowProvider("http://john.doe.myopenid.com"))
        self.failUnless(plugin.allowProvider("http://youropenid.com/john.doe"))
        self.failUnless(plugin.allowProvider("jane.doe.otherprovider.com"))


    def testAllowProvider_missing_identity(self):
        """Check default policy when we have no identity."""
        plugin=self.createPlugin()
        self.failIf(plugin.allowProvider(None))

    def testAllowProvider_blacklist(self):
        """Check provider blacklisting."""
        plugin=self.createPlugin()
        plugin.provider_blacklist = ("http://myopenid.com", "http://youropenid.com")

        self.assertEquals(
            plugin.getProperty("provider_blacklist"),
            ("http://myopenid.com", "http://youropenid.com"))

        # Domain name based identity URLs
        self.failIf(plugin.allowProvider("http://john.doe.myopenid.com"))
        self.failIf(plugin.allowProvider("http://john.doe.youropenid.com"))
        self.failUnless(plugin.allowProvider("http://jane.doe.otherprovider.com"))

        # Path name based identity URLs
        self.failIf(plugin.allowProvider("http://myopenid.com/john.doe"))
        self.failIf(plugin.allowProvider("http://youropenid.com/john.doe"))
        self.failUnless(plugin.allowProvider("http://otherprovider.com/jane.doe"))

        # Identity URLs without protocol scheme
        self.failIf(plugin.allowProvider("john.doe.myopenid.com"))
        self.failIf(plugin.allowProvider("youropenid.com/john.doe"))
        self.failUnless(plugin.allowProvider("john.doe.otherprovider.com"))

    def testAllowProvider_whitelist(self):
        """Check provider whitelisting."""
        plugin=self.createPlugin()
        plugin.provider_whitelist = ("http://myopenid.com", "http://youropenid.com")

        self.assertEquals(
            plugin.getProperty("provider_whitelist"),
            ("http://myopenid.com", "http://youropenid.com"))

        # Domain name based identity URLs
        self.failUnless(plugin.allowProvider("http://john.doe.myopenid.com"))
        self.failUnless(plugin.allowProvider("http://john.doe.youropenid.com"))
        self.failIf(plugin.allowProvider("http://jane.doe.otherprovider.com"))

        # Path name based identity URLs
        self.failUnless(plugin.allowProvider("http://myopenid.com/john.doe"))
        self.failUnless(plugin.allowProvider("http://youropenid.com/john.doe"))
        self.failIf(plugin.allowProvider("http://otherprovider.com/jane.doe"))

        # Identity URLs without protocol scheme
        self.failUnless(plugin.allowProvider("john.doe.myopenid.com"))
        self.failUnless(plugin.allowProvider("youropenid.com/john.doe"))
        self.failIf(plugin.allowProvider("john.doe.otherprovider.com"))

    def testAllowProvider_whitelist_preference(self):
        """Check that whitelisted providers take preference over blacklisted
        ones.
        """
        plugin=self.createPlugin()
        plugin.provider_blacklist = ("http://myopenid.com",)
        plugin.provider_whitelist = ("http://myopenid.com",)

        self.assertEquals(
            plugin.getProperty("provider_blacklist"),
            ("http://myopenid.com",))
        self.assertEquals(
            plugin.getProperty("provider_whitelist"),
            ("http://myopenid.com",))

        self.failUnless(plugin.allowProvider("http://john.doe.myopenid.com"))

    def test_getHTTPDomain(self):
        plugin=self.createPlugin()
        self.assertEquals("provider.com",
            plugin._getHTTPDomain("http://provider.com"))
        self.assertEquals("provider.com",
            plugin._getHTTPDomain("http://provider.com/"))
        self.assertEquals("provider.com",
            plugin._getHTTPDomain("http://provider.com/foo/bar"))
        self.assertEquals("provider.com",
            plugin._getHTTPDomain("provider.com"))
        self.assertEquals("provider.com",
            plugin._getHTTPDomain("provider.com/"))
        self.assertEquals("provider.com",
            plugin._getHTTPDomain("provider.com/foo/bar"))

    def testGetSRegAttributeInfo_empty_attributes(self):
        plugin=self.createPlugin()
        self.assertEquals(plugin.getProperty("sreg_attributes"), tuple())
        self.assertEquals(0, len(plugin.getSRegAttributeInfo()))

    def testGetSRegAttributeInfo(self):
        """Check Simple Registration attribute mappings."""
        plugin=self.createPlugin()
        plugin.sreg_attributes = (
            # 1:1 mappings
            "fullname fullname",
            "email email",
            # Aliasing
            "location country",
            "birthdate dob",
            # Duplicate values
            "location country",
            # Invalid SReg attribute
            "foobar invalid",
            )
        plugin.sreg_attributes_required = ("country", "dob")

        self.assertEquals(plugin.getProperty("sreg_attributes"),
            ("fullname fullname", "email email", "location country",
             "birthdate dob", "location country", "foobar invalid"))
        self.assertEquals(
            plugin.getProperty("sreg_attributes_required"),
            ("country", "dob"))

        self.assertEquals(plugin.getSRegAttributeInfo(), set([
            ('email', 'email', False),
            ('country', 'location', True),
            ('dob', 'birthdate', True),
            ('fullname', 'fullname', False)]))

    def testGetAXAttributeInfo_empty_attributes(self):
        plugin=self.createPlugin()
        self.assertEquals(plugin.getProperty("ax_attributes"), tuple())
        self.assertEquals(0, len(plugin.getAXAttributeInfo()))

    def testGetAXAttributeInfo(self):
        """Check Attribute Exchange attribute mappings."""
        plugin=self.createPlugin()
        plugin.ax_attributes = (
            "fullname http://axschema.org/namePerson",
            "location http://axschema.org/contact/country/home",
            "language http://axschema.org/pref/language",
            "email http://axschema.org/contact/email",
            # Duplicate value
            "language http://axschema.org/pref/language",
            )
        plugin.ax_attributes_required = (
            "fullname", # alias
            "http://axschema.org/contact/email", # type_uri
            )

        self.assertEquals(plugin.getProperty("ax_attributes"), (
            "fullname http://axschema.org/namePerson",
            "location http://axschema.org/contact/country/home",
            "language http://axschema.org/pref/language",
            "email http://axschema.org/contact/email",
            "language http://axschema.org/pref/language"))
        self.assertEquals(
            plugin.getProperty("ax_attributes_required"),
            ("fullname", "http://axschema.org/contact/email"))

        self.assertEquals(plugin.getAXAttributeInfo(), set([
            ('http://axschema.org/namePerson', 'fullname', True),
            ('http://axschema.org/contact/country/home', 'location', False),
            ('http://axschema.org/contact/email', 'email', True),
            ('http://axschema.org/pref/language', 'language', False)]))


def test_suite():
    from unittest import TestSuite, makeSuite
    suite=TestSuite()
    suite.addTest(makeSuite(TestOpenIdExtraction))
    return suite
