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

const Errors = require( 'futoin-asyncsteps/Errors' );

const BaseService = require( './lib/BaseService' );
const MasterAuthFace = require( './MasterAuthFace' );

const {
    EVTGEN_FACE,
    SVKEY_FACE,
} = require( './lib/main' );

const secutil = require( './lib/util' );


/**
 * FTN8.2: Master Auth Service
 */
class MasterAuthService extends BaseService {
    static get IFACE_IMPL() {
        return MasterAuthFace;
    }

    _checkMasterAuth( as ) {
        if ( !this._scope.master_auth ) {
            as.error( Errors.SecurityError, 'Master auth is disabled' );
        }
    }

    _checkCommon( as, _reqinfo ) {
        this._checkMasterAuth( as );
        //---
    }

    checkMAC( as, reqinfo ) {
        this._checkCommon( as, reqinfo );
        as.add( ( as, auth_info ) => reqinfo.result( auth_info ) );
    }

    genMAC( as, _reqinfo ) {
    }

    exposeDerivedKey( as, reqinfo ) {
        this._checkCommon( as, reqinfo );
        as.add( ( as, _auth_info, _dsid ) => {
        } );
    }

    getNewEncryptedSecret( as, reqinfo ) {
        this._checkMasterAuth( as );
        //---

        const ccm = reqinfo.ccm();
        const evtgen = ccm.iface( EVTGEN_FACE );
        const svkey = ccm.iface( SVKEY_FACE );

        //---
        const { msid } = reqinfo.info.RAW_REQUEST.sec || {};

        if ( !msid ) {
            as.error( Errors.InvokerError,
                'Can not be used by AuthService itself' );
        }
        //---

        const params = reqinfo.params();
        const { type, pubkey } = params;
        const scope = params.scope || '';

        // Verify user
        svkey.getKeyInfo( as, msid );
        as.add( ( as, key_info ) => {
            const old_ext_id = key_info.ext_id;
            const user = key_info.params.local_id;

            secutil.checkUser( as, ccm, user );

            // Clear all user keys except the current one
            svkey.listKeys( as, `${user}:MSTR:` );
            as.add( ( as, keys ) => {
                as.forEach( keys, ( as, _, key_id ) => {
                    if ( key_id == msid ) {
                        return;
                    }

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

            // Find out new ID
            let new_ext_id = old_ext_id;

            for ( let i = 1;
                ( i < 3 ) && ( new_ext_id === old_ext_id );
                ++i
            ) {
                new_ext_id = `${user}:MSTR:${scope}:${i}`;
            }

            // Generate a new master key
            svkey.generateKey(
                as,
                new_ext_id,
                [ 'shared', 'derive' ],
                'HMAC',
                {
                    bits : this._scope.config.key_bits,
                    local_id : user,
                    global_id : key_info.params.global_id,
                }
            );
            as.add( ( as, key_id ) => {
                evtgen.addEvent( as, 'MSTR_NEW', { user, key_id, scope } );
                svkey.pubEncryptedKey( as, key_id, { type, pubkey } );
                as.add( ( as, key_data ) => {
                    reqinfo.result( {
                        id: key_id,
                        esecret: key_data.toString( 'base64' ),
                    } );
                } );
            } );
        } );
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
