######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

# !/bin/python

from lib.boto3_util import create_resource

dynamodb_resource = create_resource('dynamodb')

class DDB(object):
    def __init__(self, log, table_name):
        self.log = log
        self.table_name = table_name
        self.table = dynamodb_resource.Table(self.table_name)

    # DDB API call to put an item
    def put_item(self, item):
        try:
            response = self.table.put_item(
                Item=item
            )
            return response
        except Exception as e:
            self.log.error(e)
            self.log.error("dynamodblib: failed to put item: \n{}".format(item))
            return None
