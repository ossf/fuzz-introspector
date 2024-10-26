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
from flask_smorest import Api
from typing import Optional, Tuple
import webapp
from webapp import routes


def create_app():
    app = Flask(__name__)
    app.config["API_TITLE"] = "Fuzz Introspector Web API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config[
        "OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.register_blueprint(routes.blueprint)

    api = Api(app)
    api.register_blueprint(routes.api_blueprint)

    try:
        routes.gtag = os.environ['G_ANALYTICS_TAG']
        print("google tag set")
    except KeyError:
        print("Not setting google tag")
        routes.gtag = None

    try:
        routes.is_local = bool(os.environ['FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ'])
        routes.local_oss_fuzz = os.environ['FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ']
        print('Local webapp is set')
    except KeyError:
        print('Using remote version of webapp')
        routes.is_local = False

    if not routes.is_local:
        try:
            routes.allow_shutdown = bool(
                os.environ['FUZZ_INTROSPECTOR_SHUTDOWN'])
            print('Local webapp is set')
        except KeyError:
            print('Using remote version of webapp')
            routes.allow_shutdown = False

    webapp.load_db()

    return app


if __name__ == "__main__":
    ssl_cert = os.getenv('FI_SSL_CERT', '')
    ssl_key = os.getenv('FI_SSL_KEY', '')
    ssl_context: Optional[Tuple[str, str]] = None
    if ssl_cert and ssl_key:
        ssl_context = (ssl_cert, ssl_key)

    create_app().run(debug=False,
                     host="0.0.0.0",
                     ssl_context=ssl_context,
                     port=int(os.environ.get("WEBAPP_PORT", '8080')))
