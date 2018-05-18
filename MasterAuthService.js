'use strict';

/**
 * @file
 *
 * Copyright 2018 FutoIn Project (https://futoin.org)
 * Copyright 2018 Andrey Galkin <andrey@futoin.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const BaseService = require( './lib/BaseService' );
const MasterAuthFace = require( './MasterAuthFace' );

/**
 * FTN8.2: Master Auth Service
 */
class MasterAuthService extends BaseService {
    static get IFACE_IMPL() {
        return MasterAuthFace;
    }

    checkMAC( as, _reqinfo ) {
    }

    genMAC( as, _reqinfo ) {
    }

    exposeDerivedKey( as, _reqinfo ) {
    }

    getNewEncryptedSecret( as, _reqinfo ) {
    }

    /**
     * Register futoin.auth.master interface with Executor
     * @alias MasterAuthService.register
     * @param {AsyncSteps} as - steps interface
     * @param {Executor} executor - executor instance
     * @param {object} options - implementation defined options
     * @param {Executor} options.scope=main.globalScope
     * @returns {MasterAuthService} instance
     */
}

module.exports = MasterAuthService;
