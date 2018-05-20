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


const path = require( 'path' );

exports = module.exports = {
    specDirs : path.resolve( __dirname, '..', 'specs' ),

    PING_VERSION: '1.0',
    FTN8_VERSION: '0.3',

    DB_IFACEVER : 'futoin.db.l2:1.0',
    DB_USERS_TABLE : 'sec_users',

    MANAGE_FACE : '#ftnsec.manage',
    SVKEY_FACE : '#ftnsec.key',
    SVDATA_FACE : '#ftnsec.data',
    EVTGEN_FACE : '#evtgen.ftnsec',
    EVTPUSH_FACE : '#evtpush.ftnsec',
    STLS_AUTH_FACE : '#ftnsec.stls.auth',
    STLS_MANAGE_FACE : '#ftnsec.stls.manage',
    MASTER_AUTH_FACE : '#ftnsec.master.auth',
    MASTER_MANAGE_FACE : '#ftnsec.master.manage',
    MASTER_AUTOREG_FACE : '#ftnsec.master.autoreg',

    scopeTemplate : {
        config: {
            domains: [],
            clear_auth: false,
            mac_auth: false,
            master_auth: false,
            master_auto_reg: false,
            auth_service: false,
            password_len: 16,
            key_bits: 256,
            def_user_ms_max: 0,
            def_service_ms_max: 10, // up to 5 due to rotiation
        },
        domain2service: {},
        system_local_id : null,
    },
};

Object.freeze( exports );
Object.freeze( exports.scopeTemplate );
Object.freeze( exports.scopeTemplate.config );
