import boto3
import logging
import os
import re
from botocore.exceptions import ClientError
from cfn_resource_provider import ResourceProvider

log = logging.getLogger()
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


request_schema = {
    "type": "object",
            "required": ["UserName", "SSHPublicKeyBody"],
            "properties": {
                "UserName": {"type": "string", "minLength": 1, "pattern": "[a-zA-Z0-9_/]+",
                             "description": "the name of the user to upload the key for"},
                "SSHPublicKeyBody": {"type": "string",
                                     "description": "the content of the public SSH key"},
            }
}

class IAMPublicKeyProvider(ResourceProvider):

    def __init__(self):
        super(IAMPublicKeyProvider, self).__init__()
        self._value = None
        self.request_schema = request_schema
        self.region = boto3.session.Session().region_name
        self.account_id = (boto3.client('sts')).get_caller_identity()['Account']
        self.iam = boto3.client('iam')

    def upload_ssh_public_key(self):
        try:
            response = self.iam.upload_ssh_public_key(UserName=self.get('UserName'), SSHPublicKeyBody=self.get('SSHPublicKeyBody'))
            self.key_id = response['SSHPublicKey']['SSHPublicKeyId']
            self.set_attribute('SSHPublicKeyId', self.key_id)
            self.physical_resource_id = self.key_id
        except ClientError as e:
            self.physical_resource_id = 'could-not-create'
            self.fail(str(e))

        return self.status == 'SUCCESS'

    def delete_ssh_public_key(self, key_id):
        try:
            self.iam.delete_ssh_public_key(UserName=self.get('UserName'), SSHPublicKeyId=key_id)
        except ClientError as e:
            self.fail(str(e))

        return self.status == 'SUCCESS'

    def create(self):
        self.upload_ssh_public_key()

    def update(self):
        key_id = self.physical_resource_id
        if key_id is None:
            self.fail('could not get the key id from the physical resource id, %s' % self.physical_resource_id)
            return

        # update of the key, delete first
        if self.delete_ssh_public_key(key_id):
            self.upload_ssh_public_key()

    def delete(self):
        key_id = self.physical_resource_id
        if key_name is not None:
            try:
                self.delete_ssh_public_key(key_id)
            except ClientError as e:
                self.fail(str(e))
                return
            self.success('ssh key with the id %s is deleted' % key_id)
        else:
            self.success('ssh key with the id %s is ignored' % self.physical_resource_id)

provider = IAMPublicKeyProvider()

def handler(request, context):
    return provider.handle(request, context)
