OpenID PAS support
==================

Introduction
------------

This product implements OpenID_ authentication support for Zope_ via a
Pluggable Authentication Service plugin. 

Using this package everyone with an OpenID authentity will be able to
login on your Zope site. OpenID accounts are not given any extra roles
beyond the standard Authenticated role. This allows you to make a distinction
between people that have explicitly signed up to your site and people
who are unknown but have successfully verified their identity.

.. _Zope: http://www.zope.org/
.. _OpenID: http://www.openidenabled.com/

Authentication flow
-------------------

The OpenID authentication flow goes like this:

- user submits a OpenID identity (which is a URL) to you site. This is done
  through a HTTP POST using a form variable called ``__ac_identity_url``

- the PAS plugin sees this variable during credential extraction and initiates
  a OpenID challenge. This results in a transaction commit and a redirect to
  an OpenID server.

- the OpenID server takes care of authenticating the user and redirect the
  user back to the Zope site.

- the OpenID PAS plugin extracts the information passed in via the OpenID
  server redirect and uses that in its authentication code to complete the
  OpenID authentication

Session management
------------------

The PAS plugin only takes care of authenticating users. In almost all
environments it will be needed to also setup a session so users stay
logged in when they visit another page. This can be done via a special
session management PAS plugin, for example `plone.session`_.

Provider selection
------------------

By default the plugin accepts any OpenID compliant provider to authenticate
users. However, the list of accepted providers can be configured using either
a blacklist or a whitelist with the following properties.

**Provider whitelist (provider_whitelist)**

  List of provider domains that are allowed to authenticate users for the
  plugin. The providers must be defined using their primary addresses, e.g.
  ``http://myopenid.com/``. The identity URLs provided by the user will be
  matched against these addresses to decide whether authentication will be
  accepted.
  
  To check will be performed both in the initiation phase (against the
  claimed id) and the response phase (against the provider supplied id) and
  will work for delegated identity urls also.

  Any identifier that does not match the providers given in this list will be
  rejected. An empty value will disable whitelist checking.

**Provider blacklist (provider_blacklist)**

  List of provider domains that are disallowed to authenticate users for the
  plugin. The providers must be defined using their primary addresses, e.g.
  ``http://myopenid.com/``. The identity URLs provided by the user will be
  matched against these addresses to decide whether authentication will be
  accepted.
  
  To check will be performed both in the initiation phase (against the
  claimed id) and the response phase (against the provider supplied id) and
  will work for delegated identity urls also.

  Any identifier that does matches the providers given in this list will be
  rejected. An empty value will disable blacklist checking.

Simple Registration extension
-----------------------------

OpenID `Simple Registration
<http://openid.net/specs/openid-simple-registration-extension-1_0.html>`_
(SReg) is an extension to the OpenID Authentication protocol that allows for
very light-weight profile exchange. It is designed to pass nine commonly
requested pieces of information when an End User goes to register a new
account with a web service.

The plugin supports requesting the SReg profile information from the OpenID
provider and exposes it through the ``IPropertiesPlugin`` interface as user
properties. The SReg property fields can be mapped to a customizable set of
property names to integrate them with the Relying Party policy. Configuration
of the extension is managed using the following properties

**Enable SReg (sreg_enabled)**

  Boolean property to enable / disable the use of the Simple Registration
  extension during OpenID authentication.

**SReg attributes (sreg_attributes)**

  List of "``<alias> <sreg_attribute_name>``" tokens, one per line, that will
  be requested from the OpenID provider. The ``<alias>`` is the local name for
  the attribute that will appear in the
  ``IPropertiesPlugin.getPropertiesForUser()`` result as the key for the given
  attribute. The ``<sreg_attribute_name>`` must be one of the nine property
  names defined for SReg. Unknown attribute names will be ignored.

  For example,
  ::

    fullname fullname
    location country
    language language
    email email

  maps the SReg attributes "fullname", "country", "language" and "email" and
  makes them available through ``IPropertiesPlugin.getPropertiesForUser()``
  under local names "fullname", "location", "language" and "email"
  respectively.
  
  The specified attributes for Simple Registration are:
  
  - fullname
  - nickname
  - dob
  - email
  - gender
  - postcode
  - country
  - language
  - timezone

**Required SReg attributes (sreg_attributes_required)**

  List of attributes that are marked as required in the SReg request. The
  attributes must reference valid SReg attribute names that are present in the
  ``sreg_attributes`` property. Unknown attributes will be ignored. Note that
  it is possible for the OpenID provider to omit attributes marked required
  and it is up to the Relying Party to decide how to handle the situation.

Attribute Exchange extension
----------------------------

OpenID `Attribute Exchange
<http://openid.net/specs/openid-attribute-exchange-1_0.html>`_ (AX) is an
OpenID service extension for exchanging identity information between
endpoints.

The plugin supports requesting the AX profile information from the OpenID
provider and exposes it through the ``IPropertiesPlugin`` interface as user
properties. The AX property fields can be mapped to a customizable set of
property names to integrate them with the Relying Party policy. Configuration
of the extension is managed using the following properties

**Enable AX (ax_enabled)**

  Boolean property to enable / disable the use of the Attribute Exchange
  extension during OpenID authentication.

**AX attributes (ax_attributes)**

  List of "``<alias> <ax_type_uri>``" tokens, one per line, that will
  be requested from the OpenID provider. The ``<alias>`` is the local name for
  the attribute that will appear in the
  ``IPropertiesPlugin.getPropertiesForUser()`` result as the key for the given
  attribute. The ``<ax_type_uri>`` is a type URI for the particular attribute.
  
  The type URIs may be chosen arbitrarily as long as both the Relying Party
  and the OpenID provider both support them. There exists a community driven
  effort to create a common AX schema for a set of attribute types at
  http://www.axschema.org/types/.

  For example,
  ::

    fullname http://axschema.org/namePerson
    location http://axschema.org/contact/country/home
    language http://axschema.org/pref/language
    email http://axschema.org/contact/email

  maps the AX attributes that are equivalent to the SReg attributes
  "fullname", "country", "language" and "email" and makes them available
  through ``IPropertiesPlugin.getPropertiesForUser()`` under local names
  "fullname", "location", "language" and "email" respectively.


**Required AX attributes (ax_attributes_required)**

  List of attributes that are marked as required in the AX request. The
  attributes may be referenced by either alias or the AX type URI and
  must exist in the ``ax_attributes`` property. Unknown attributes will be
  ignored. Note that it is possible for the OpenID provider to omit attributes
  marked required and it is up to the Relying Party to decide how to handle
  the situation.
  
  Some OpenID providers (such as Google) may fail to include the requested
  attributes in the response unless they are marked explicitly being required.

In case both the Simple Registration and Attribute Exchange extensions are
enabled the plugin first reads the attributes received through the SReg
response and then updates the values with the attributes received from the AX
response. This means that if the local aliased names for both extensions
contain identical names then the values from the AX response will override
the values from the SReg response.

Strict attribute requirements
-----------------------------

It is possible to mark the Simple Registration and Attribute Exchange
attributes as required using the properties defined above. However, it is up
to the provider and the user to decide whether to return these attributes as
part of the authentication response.

By default, the plugin will accept successful authentication responses even if
the required attributes are missing. It is possible to enable a strict mode
for the required attributes that will reject successful authentication
responses in case any of the required attributes are missing.

**Strict required attributes (strict_required_attributes)**

  Boolean property that enables strict mode for required attributes.
  Authentication will be rejected if any of the required attributes are
  missing.

.. _plone.session: http://pypi.python.org/pypi/plone.session

