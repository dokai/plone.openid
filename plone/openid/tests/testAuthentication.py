# -*- coding: utf-8 -*-
import unittest


class MockConsumer(object):
    """Mock consumer that returns crafted OpenID responses"""

    def __init__(self, identity):
        self.identity = identity

    def complete(self, credentials, current_url):
        from plone.openid.tests.utils import makeSuccessResponse
        self.credentials = credentials
        self.current_url = current_url
        self.response = makeSuccessResponse(self.identity, credentials)
        return self.response


class TestOpenIdAuthentication(unittest.TestCase):
    identity = "http://plone.myopenid.com"

    def createPlugin(self):
        from plone.openid.tests.utils import MockPAS
        from plone.openid.plugins.oid import OpenIdPlugin
        plugin=OpenIdPlugin("openid")
        pas=MockPAS()
        return plugin.__of__(pas)

    def enableSReg(self, plugin, attributes, required, strict_mode=False):
        """Enables the Simple Registration extension for the given plugin."""
        plugin.sreg_enabled = True
        plugin.sreg_attributes = tuple(
            "%s %s" % (alias, field)
            for alias, field
            in attributes.iteritems())
        plugin.sreg_attributes_required = required
        plugin.strict_required_attributes = strict_mode

        # Check that plugin is in correct state before the actual tests
        self.failUnless(plugin.getProperty("sreg_enabled", False))
        self.assertEquals(
            attributes,
            dict((alias, field) for alias, field
                 in (line.split(None, 2) for line
                     in plugin.getProperty("sreg_attributes"))))
        self.assertEquals(
            plugin.getProperty("sreg_attributes_required"), required)
        self.assertEquals(
            plugin.getProperty("strict_required_attributes"), strict_mode)

    def enableAX(self, plugin, attributes, required, strict_mode=False):
        """Enables the Attribute Exchange extension for the given plugin."""
        plugin.ax_enabled = True
        plugin.ax_attributes = tuple(
            "%s %s" % (alias, type_uri)
            for alias, type_uri
            in attributes.iteritems())
        plugin.ax_attributes_required = required
        plugin.strict_required_attributes = strict_mode

        # Check that plugin is in correct state before the actual tests
        self.failUnless(plugin.getProperty("ax_enabled", False))
        self.assertEquals(
            attributes,
            dict((alias, type_uri) for alias, type_uri
                 in (line.split(None, 2) for line
                     in plugin.getProperty("ax_attributes"))))
        self.assertEquals(
            plugin.getProperty("ax_attributes_required"), required)
        self.assertEquals(
            plugin.getProperty("strict_required_attributes"), strict_mode)

    def buildServerResponse(self, sreg=None, ax=None):
        credentials={}
        for field in ["nonce", "openid.assoc_handle", "openid.return_to",
                      "openid.signed", "openid.sig",
                      "openid.invalidate_handle", "openid.mode"]:
            credentials[field]=field
        credentials["openid.identity"]=self.identity
        credentials["openid.source"]="server"

        # this isn't part of the server response, but is added to the
        # credentials by PAS
        credentials["extractor"] = "openid"

        if sreg is not None:
            credentials.update(sreg)

        if ax is not None:
            credentials.update(ax)

        return credentials

    def testEmptyAuthentication(self):
        """Test if we do not invent an identity out of thin air.
        """
        plugin=self.createPlugin()
        creds=plugin.authenticateCredentials({})
        self.assertEqual(creds, None)

    def testEmptyStringIdentityAuthentication(self):
        """Test coverage for bug #7176, where an
           "" (i.e. an empty string) identity passed to
           authenticationCredentials should return fail authentication
        """
        credentials=self.buildServerResponse()
        credentials["openid.identity"]=""
        plugin=self.createPlugin()
        creds=plugin.authenticateCredentials(credentials)
        self.assertEqual(creds, None)

    def testUnknownOpenIdSource(self):
        """Test if an incorrect source does not produce unexpected exceptions.
        """
        plugin=self.createPlugin()
        creds=plugin.authenticateCredentials({"openid.source": "x"})
        self.assertEqual(creds, None)

    def testIncompleteServerAuthentication(self):
        """Test authentication of OpenID server responses.
        """
        credentials=self.buildServerResponse()
        del credentials["openid.sig"]
        plugin=self.createPlugin()
        creds=plugin.authenticateCredentials(credentials)
        self.assertEqual(creds, None)

    def testSRegResponse(self):
        """Tests a successful OpenID response with Simple Registration data
        with all required fields present in the response.
        """
        plugin=self.createPlugin()

        self.enableSReg(plugin, {
            "fullname": "fullname",
            "email": "email",
            "location": "country",
            "birthdate": "dob",
            "foobar": "invalid",
            }, ("country", "dob"))

        self.assertEquals(0, len(plugin._attribute_store))

        # The values contain UTF-8 encoded string on purpose.
        credentials = self.buildServerResponse(sreg={
            "sreg.fullname": "Jöhn Döe",
            "sreg.email": "john@doe.com",
            "sreg.country": "Finland",
            "sreg.dob": "1979-01-01",
            })

        # Patch the plugin to return our crafted SReg response
        plugin.getConsumer = lambda: MockConsumer(self.identity)
        creds=plugin.authenticateCredentials(credentials)

        # Assert that SReg attributes were received and stored correctly.
        # The UTF-8 encoded values are decoded properly to unicode objects.
        self.assertEquals(dict(plugin._attribute_store[self.identity]), {
            "fullname": u"Jöhn Döe",
            "email": u"john@doe.com",
            "location": u"Finland",
            "birthdate": u"1979-01-01",
        })
        # Assert that PAS authentication was successful
        self.assertEquals((self.identity, self.identity), creds)

    def testSRegResponse_missing_attributes_strict_required(self):
        """Tests a successful OpenID response with Simple Registration data
        with some of the required fields missing from the response and with
        the strict required attributes mode enabled.
        """
        plugin=self.createPlugin()
        # Configure SReg extension
        self.enableSReg(plugin,
            attributes={
                "fullname": "fullname",
                "email": "email",
                "location": "country",
                "birthdate": "dob",
                "foobar": "invalid",
                },
            required=("country", "dob"),
            strict_mode=True)

        self.assertEquals(0, len(plugin._attribute_store))

        # The values contain UTF-8 encoded string on purpose.
        credentials = self.buildServerResponse(sreg={
            "sreg.fullname": "Jöhn Döe",
            "sreg.email": "john@doe.com",
            "sreg.country": "Finland",
            })

        # Patch the plugin to return our crafted SReg response
        plugin.getConsumer = lambda: MockConsumer(self.identity)
        creds=plugin.authenticateCredentials(credentials)

        # Assert that authentication failed and user attributes were not
        # stored.
        self.failIf(self.identity in plugin._attribute_store)
        self.assertEquals(None, creds)

    def testAXResponse(self):
        """Tests a successful OpenID response with Attribute Exchange data
        with all required fields present in the response.
        """
        plugin=self.createPlugin()

        self.enableAX(plugin, {
            "fullname": "http://axschema.org/namePerson",
            "location": "http://axschema.org/contact/country/home",
            "language": "http://axschema.org/pref/language",
            "email": "http://axschema.org/contact/email",
            }, ("fullname", "http://axschema.org/contact/country/home"))

        self.assertEquals(0, len(plugin._attribute_store))

        # The values contain UTF-8 encoded string on purpose.
        credentials = self.buildServerResponse(ax={
            "ns.ax": "http://openid.net/srv/ax/1.0",
            "ax.mode": "fetch_response",
            "ax.type.fullname": "http://axschema.org/namePerson",
            "ax.type.location": "http://axschema.org/contact/country/home",
            "ax.type.language": "http://axschema.org/pref/language",
            "ax.type.email": "http://axschema.org/contact/email",
            "ax.value.fullname": "Jöhn Döe",
            "ax.value.location": "Finland",
            "ax.value.language": "Finnish",
            "ax.count.email": "1",
            "ax.value.email.1": "john@doe.com",
            })

        # Patch the plugin to return our crafted AX response
        plugin.getConsumer = lambda: MockConsumer(self.identity)
        creds=plugin.authenticateCredentials(credentials)

        # Assert that AX attributes were received and stored correctly.
        # The UTF-8 encoded values are decoded properly to unicode objects.
        self.assertEquals(dict(plugin._attribute_store[self.identity]), {
            "fullname": u"Jöhn Döe",
            "email": u"john@doe.com",
            "location": u"Finland",
            "language": u"Finnish",
        })
        # Assert that PAS authentication was successful
        self.assertEquals((self.identity, self.identity), creds)

    def testAXResponse_missing_attributes_strict_required(self):
        """Tests a successful OpenID response with Attribute Exchange data
        with some of the required fields missing from the response and with
        the strict required attributes mode enabled.
        """
        plugin=self.createPlugin()

        self.enableAX(plugin,
            attributes={
                "fullname": "http://axschema.org/namePerson",
                "location": "http://axschema.org/contact/country/home",
                "language": "http://axschema.org/pref/language",
                "email": "http://axschema.org/contact/email",
                },
            required=("fullname", "http://axschema.org/contact/country/home"),
            strict_mode=True)

        self.assertEquals(0, len(plugin._attribute_store))

        # The values contain UTF-8 encoded string on purpose.
        credentials = self.buildServerResponse(ax={
            "ns.ax": "http://openid.net/srv/ax/1.0",
            "ax.mode": "fetch_response",
            "ax.count.location": "0",
            "ax.type.language": "http://axschema.org/pref/language",
            "ax.type.email": "http://axschema.org/contact/email",
            "ax.value.language": "Finnish",
            "ax.count.email": "1",
            "ax.value.email.1": "john@doe.com",
            })

        # Patch the plugin to return our crafted AX response
        plugin.getConsumer = lambda: MockConsumer(self.identity)
        creds = plugin.authenticateCredentials(credentials)

        # Assert that authentication failed and user attributes were not
        # stored.
        self.failIf(self.identity in plugin._attribute_store)
        self.assertEquals(None, creds)

    def testCombinedAttributeResponse(self):
        """Tests a successful OpenID response that contains both the Simple
        Registration and Attribute Exchange attributes.
        """
        plugin=self.createPlugin()

        self.enableAX(plugin, {
            "fullname": "http://axschema.org/namePerson",
            "location": "http://axschema.org/contact/country/home",
            "language": "http://axschema.org/pref/language",
            "email": "http://axschema.org/contact/email",
            }, ("fullname", "http://axschema.org/contact/country/home"))

        self.enableSReg(plugin, {
            "fullname": "fullname",
            "email": "email",
            "location": "country",
            "birthdate": "dob",
            "foobar": "invalid",
            }, ("country", "dob"))

        self.assertEquals(0, len(plugin._attribute_store))

        # The values contain UTF-8 encoded string on purpose.
        credentials = self.buildServerResponse(
            sreg={
                "sreg.fullname": "Jöhn Döe",
                "sreg.email": "john@doe.com",
                "sreg.country": "Finland",
                "sreg.dob": "1979-01-01",
                },
            ax={
                "ns.ax": "http://openid.net/srv/ax/1.0",
                "ax.mode": "fetch_response",
                "ax.type.fullname": "http://axschema.org/namePerson",
                "ax.type.location": "http://axschema.org/contact/country/home",
                "ax.type.language": "http://axschema.org/pref/language",
                "ax.type.email": "http://axschema.org/contact/email",
                "ax.value.fullname": "Jäne Döe",
                "ax.value.location": "Finland",
                "ax.value.language": "Finnish",
                "ax.count.email": "1",
                "ax.value.email.1": "jane@doe.com",
                })

        # Patch the plugin to return our crafted response
        plugin.getConsumer = lambda: MockConsumer(self.identity)
        creds = plugin.authenticateCredentials(credentials)

        # Assert that both SReg and AX attributes were received and stored
        # correctly and in the case of overlapping local aliases the values
        # from the AX response took preference.
        self.assertEquals(dict(plugin._attribute_store[self.identity]), {
            "fullname": u"Jäne Döe",
            "email": u"jane@doe.com",
            "location": u"Finland",
            "language": u"Finnish",
            "birthdate": u"1979-01-01",
        })
        # Assert that PAS authentication was successful
        self.assertEquals((self.identity, self.identity), creds)


    def testAdditiveAttributes(self):
        """Checks that OpenID attributes are additive across authentication
        responses.
        """
        plugin=self.createPlugin()

        self.enableSReg(plugin,
            attributes={
                "fullname": "fullname",
                "email": "email",
                "location": "country",
                "birthdate": "dob",
                "foobar": "invalid",
                },
            required=("fullname", "email"))

        self.assertEquals(0, len(plugin._attribute_store))
        # Patch the plugin to return our crafted SReg response
        plugin.getConsumer = lambda: MockConsumer(self.identity)

        # First login with the initial attributes
        credentials = self.buildServerResponse(sreg={
            "sreg.fullname": "Jöhn Döe",
            "sreg.email": "john@doe.com",
            })
        creds = plugin.authenticateCredentials(credentials)

        self.assertEquals(dict(plugin._attribute_store[self.identity]), {
            "fullname": u"Jöhn Döe",
            "email": u"john@doe.com",
        })
        self.assertEquals((self.identity, self.identity), creds)
        self.assertEquals(1, len(plugin._attribute_store))

        # Second login with a different, overlapping set of attributes
        credentials = self.buildServerResponse(sreg={
            "sreg.email": "john.doe@work.com",
            "sreg.country": "Finland",
            "sreg.dob": "1979-01-01",
            })
        creds = plugin.authenticateCredentials(credentials)

        # Assert that SReg attributes were received and stored correctly and
        # merged additively with the existing set of attributes.
        self.assertEquals(dict(plugin._attribute_store[self.identity]), {
            "fullname": u"Jöhn Döe",
            "email": u"john.doe@work.com",
            "location": u"Finland",
            "birthdate": u"1979-01-01",
        })
        self.assertEquals((self.identity, self.identity), creds)
        self.assertEquals(1, len(plugin._attribute_store))

    def testClearAttributes_all(self):
        plugin = self.createPlugin()
        self.assertEquals(0, len(plugin._attribute_store))

        plugin.clearAttributes()
        self.assertEquals(0, len(plugin._attribute_store))

        plugin._attribute_store['john.doe'] = {"fullname": u"John Doe"}
        self.assertEquals(1, len(plugin._attribute_store))

        plugin.clearAttributes()
        self.assertEquals(0, len(plugin._attribute_store))

    def testClearAttributes_single_user(self):
        plugin = self.createPlugin()
        self.assertEquals(0, len(plugin._attribute_store))

        plugin._attribute_store['john.doe'] = {"fullname": u"John Doe"}
        plugin._attribute_store['jane.doe'] = {"fullname": u"Jane Doe"}
        self.assertEquals(2, len(plugin._attribute_store))

        plugin.clearAttributes('john.doe')
        self.assertEquals(1, len(plugin._attribute_store))
        self.assertEquals('jane.doe', plugin._attribute_store.keys()[0])

def test_suite():
    from unittest import TestSuite, makeSuite
    suite=TestSuite()
    suite.addTest(makeSuite(TestOpenIdAuthentication))
    return suite
