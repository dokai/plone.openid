from openid.consumer.consumer import SuccessResponse
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.message import Message

import Acquisition

def makeSuccessResponse(claimed_id, query):
    """Returns an OpenID success response with given arguments, all signed."""
    endpoint = OpenIDServiceEndpoint()
    endpoint.claimed_id = claimed_id
    signed_list = ['openid.' + k for k in query]
    return SuccessResponse(endpoint, Message.fromOpenIDArgs(query), signed_list)

class MockRequest:
    ACTUAL_URL = "http://nohost/"
    def __init__(self):
        self.form=dict(SESSION=dict())
        self.RESPONSE = None

    def __getitem__(self, key):
        return self.form.get(key)


class MockPAS(Acquisition.Implicit):
    def __init__(self):
        self.REQUEST=MockRequest()

    def updateCredentials(self, *args, **kwargs):
        pass

class MockSite(Acquisition.Implicit):

    def absolute_url(self):
        return "http://nohost/"
