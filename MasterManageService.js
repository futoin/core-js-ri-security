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
const MasterManageFace = require( './MasterManageFace' );
const Errors = require( 'futoin-asyncsteps/Errors' );

const {
    EVTGEN_FACE,
    MANAGE_FACE,
    SVKEY_FACE,
} = require( './lib/main' );

/**
 * FTN8.2: Master Auth Manage Service
 */
class MasterManageService extends BaseService {
    static get IFACE_IMPL() {
        return MasterManageFace;
    }

    getNewPlainSecret( as, reqinfo ) {
        const { config } = this._scope;

        if ( !config.master_auth ) {
            as.error( Errors.SecurityError, 'Master auth is disabled' );
        }

        const { user } = reqinfo.params();
        const ccm = reqinfo.ccm();
        const manage = ccm.iface( MANAGE_FACE );
        const evtgen = ccm.iface( EVTGEN_FACE );
        const svkey = ccm.iface( SVKEY_FACE );
        const scope = '';

        // Verify user
        manage.getUserInfo( as, user );

        as.add( ( as, user_info ) => {
            // Clear all user keys
            svkey.listKeys( as, `${user}:MSTR:` );
            as.add( ( as, keys ) => {
                as.forEach( keys, ( as, _, key_id ) => {
                    evtgen.addEvent( as, 'MSTR_DEL', { user, key_id } );
                    svkey.wipeKey( as, key_id );

                    // Remove related derived keys
                    svkey.listKeys( as, `${key_id}:DRV:` );
                    as.add( ( as, dkeys ) => {
                        as.forEach( dkeys, ( as, _, dkey_id ) => {
                            svkey.wipeKey( as, dkey_id );
                        } );
                    } );
                } );
            } );

            // Generate a single new master key
            svkey.generateKey(
                as,
                `${user}:MSTR:${scope}:1`,
                [ 'shared', 'derive' ],
                'HMAC',
                {
                    bits : config.key_bits,
                    local_id : user_info.local_id,
                    global_id : user_info.global_id,
                }
            );
            as.add( ( as, key_id ) => {
                evtgen.addEvent( as, 'MSTR_NEW', { user, key_id, scope } );
                svkey.exposeKey( as, key_id );
                as.add( ( as, key_data ) => {
                    reqinfo.result( {
                        id: key_id,
                        secret: key_data.toString( 'base64' ),
                    } );
                } );
            } );
        } );
    }

    /**
     * Register futoin.auth.master.manage interface with Executor
     * @alias MasterManageService.register
     * @param {AsyncSteps} as - steps interface
     * @param {Executor} executor - executor instance
     * @param {object} options - implementation defined options
     * @param {Executor} options.scope=main.globalScope
     * @returns {MasterManageService} instance
     */
}

module.exports = MasterManageService;
