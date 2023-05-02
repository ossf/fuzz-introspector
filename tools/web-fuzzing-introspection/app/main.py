# Copyright 2023 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from flask import Flask

import webapp
from webapp import routes


def create_app():
    app = Flask(__name__)
    app.register_blueprint(routes.blueprint)

    webapp.load_db()

    return app


if __name__ == "__main__":
    create_app().run(debug=False,
                     host="0.0.0.0",
                     port=os.environ.get("WEBAPP_PORT", 5002))
