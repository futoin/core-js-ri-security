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
const StatelessManageFace = require( './StatelessManageFace' );

const {
    EVTGEN_FACE,
    MANAGE_FACE,
    SVKEY_FACE,
} = require( './lib/main' );

/**
 * FTN8.1.: Stateless Manage Service
 */
class StatelessManageService extends BaseService {
    static get IFACE_IMPL() {
        return StatelessManageFace;
    }

    _checkUsers( as, ccm, { user, service } ) {
        const manage = ccm.iface( MANAGE_FACE );
        manage.getUserInfo( as, user );
        manage.getUserInfo( as, service );
    }

    _keyName( { user, service, for_mac } ) {
        const type = for_mac ? 'STLSMAC' : 'STLSPWD';
        return `${user}:${service}:${type}`;
    }

    genNewSecret( as, reqinfo ) {
        this.removeSecret( as, reqinfo );

        const params = reqinfo.params();
        const { for_mac } = params;
        const ccm = reqinfo.ccm();
        const { config } = this._scope;

        if ( !for_mac && !config.clear_auth ) {
            as.error( 'InternalError', 'Clear text auth is disabled' );
        } else if ( for_mac && !config.mac_auth ) {
            as.error( 'InternalError', 'Stateless MAC auth is disabled' );
        }

        // NOTE: even is not cleared on abort
        const evtgen = ccm.iface( EVTGEN_FACE );
        evtgen.addEvent( as, 'STLS_NEW', params );

        // SV generate
        const svkeys = ccm.iface( SVKEY_FACE );
        svkeys.generateKey(
            as,
            this._keyName( params ),
            [ 'shared', 'sign' ],
            for_mac ? 'HMAC' : 'Password',
            for_mac ? config.key_bits : ( config.password_len << 3 )
        );

        // SV expose
        as.add( ( as, key_id ) => {
            svkeys.exposeKey( as, key_id );
        } );
        as.add( ( as, raw_key ) => {
            const res = raw_key.toString( params.for_mac ? 'base64' : 'utf8' );
            reqinfo.result( res );
        } );
    }

    getSecret( as, reqinfo ) {
        const params = reqinfo.params();
        const ccm = reqinfo.ccm();

        // Check user
        this._checkUsers( as, ccm, params );

        // SV get key info
        const svkeys = ccm.iface( SVKEY_FACE );

        as.add(
            ( as ) => svkeys.extKeyInfo( as, this._keyName( params ) ),
            ( as, err ) => {
                if ( err === 'UnknownKeyID' ) {
                    as.error( 'NotSet' );
                }
            }
        );

        // SV expose
        as.add( ( as, key_info ) => {
            svkeys.exposeKey( as, key_info.id );
        } );
        as.add( ( as, raw_key ) => {
            const res = raw_key.toString( params.for_mac ? 'base64' : 'utf8' );
            reqinfo.result( res );
        } );
    }

    removeSecret( as, reqinfo ) {
        const params = reqinfo.params();
        const ccm = reqinfo.ccm();

        // Check user
        this._checkUsers( as, ccm, params );

        // NOTE: even is not cleared on abort
        const evtgen = ccm.iface( EVTGEN_FACE );
        evtgen.addEvent( as, 'STLS_DEL', params );

        // SV cleanup
        as.add(
            ( as ) => {
                const svkeys = ccm.iface( SVKEY_FACE );

                svkeys.extKeyInfo( as, this._keyName( params ) );

                as.add( ( as, key_info ) => {
                    svkeys.wipeKey( as, key_info.id );
                    reqinfo.result( true );
                } );
            },
            ( as, err ) => {
                if ( err === 'UnknownKeyID' ) {
                    reqinfo.result( true );
                    as.success();
                }
            }
        );
    }

    /**
     * Register futoin.auth.stateless.manage interface with Executor
     * @alias StatelessManageService.register
     * @param {AsyncSteps} as - steps interface
     * @param {Executor} executor - executor instance
     * @param {object} options - implementation defined options
     * @param {Executor} options.scope=main.globalScope
     * @returns {StatelessManageService} instance
     */
}

module.exports = StatelessManageService;
