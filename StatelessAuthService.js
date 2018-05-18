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
const StatelessAuthFace = require( './StatelessAuthFace' );
const macutils = require( './lib/macutils' );

const Errors = require( 'futoin-asyncsteps/Errors' );

const {
    MANAGE_FACE,
    SVKEY_FACE,
    SVDATA_FACE,
} = require( './lib/main' );

const empty_buf = Buffer.from( '' );

/**
 * Manage Service
 */
class StatelessAuthService extends BaseService {
    static get IFACE_IMPL() {
        return StatelessAuthFace;
    }

    _checkFingerprints( as, _ccm, _user, _client ) {
        // TODO:
    }

    _checkUser( as, ccm, user ) {
        const manage = ccm.iface( MANAGE_FACE );
        as.add(
            ( as ) => manage.getUserInfo( as, user ),
            ( as, err ) => {
                if ( err === 'UnknownUser' ) {
                    as.error( Errors.SecurityError, `Invalid user or password: ${user}` );
                }
            }
        );

        as.add( ( as, info ) => {
            if ( !info.is_enabled ) {
                as.error( Errors.SecurityError, `User is not enabled: ${user}` );
            }

            as.success( info );
        } );
    }

    _keyName( reqinfo, user, for_mac ) {
        const reqinfo_info = reqinfo.info;
        const service = ( reqinfo_info.SECURITY_LEVEL === 'System' )
            ? this._scope.system_local_id
            : reqinfo().userInfo().localID();
        const type = for_mac ? 'STLSMAC' : 'STLSPWD';
        return `${user}:${service}:${type}`;
    }


    _checkCommon( as, { reqinfo, for_mac, base, source, user, hash, sigbuf } ) {
        const ccm = reqinfo.ccm();

        this._checkUser( as, ccm, user );
        as.add(
            ( as, user_info ) => {
                this._checkFingerprints( as, ccm, user, source );

                const svkeys = ccm.iface( SVKEY_FACE );
                svkeys.extKeyInfo( as, this._keyName( reqinfo, user, for_mac ) );

                as.add( ( as, key_info ) => {
                    const svdata = ccm.iface( SVDATA_FACE );
                    svdata.verify( as, key_info.id, base, sigbuf, hash );

                    as.successStep( {
                        local_id : user_info.local_id,
                        global_id : user_info.global_id,
                    } );
                } );
            },
            ( as, err ) => {
                if ( err === 'InvalidSignature' ) {
                    as.error( Errors.SecurityError, `Invalid user or password: ${user}` );
                }
            }
        );
    }

    checkClear( as, reqinfo ) {
        if ( !this._scope.config.clear_auth ) {
            as.error( Errors.SecurityError, 'Clear text auth is disabled' );
        }

        const { source, sec : { user, secret } } = reqinfo.params();
        this._checkCommon( as, {
            reqinfo,
            for_mac: false,
            base: empty_buf,
            source,
            user,
            hash: 'NA',
            sigbuf: Buffer.from( secret, 'utf8' ),
        } );
    }

    checkMAC( as, reqinfo ) {
        if ( !this._scope.config.mac_auth ) {
            as.error( Errors.SecurityError, 'Stateless MAC auth is disabled' );
        }

        const { base, source, sec : { user, algo, sig } } = reqinfo.params();
        const { hash } = macutils.parseMode( algo );
        this._checkCommon( as, {
            reqinfo,
            for_mac: true,
            base,
            source,
            user,
            hash,
            sigbuf: Buffer.from( sig, 'base64' ),
        } );
    }

    genMAC( as, reqinfo ) {
        const { base, reqsec : { user, algo } } = reqinfo.params();
        const { hash } = macutils.parseMode( algo );
        const ccm = reqinfo.ccm();

        const svkeys = ccm.iface( SVKEY_FACE );
        svkeys.extKeyInfo( as, this._keyName( reqinfo, user, true ) );

        as.add( ( as, key_info ) => {
            const svdata = ccm.iface( SVDATA_FACE );
            svdata.sign( as, key_info.id, base, hash );

            as.add( ( as, sig ) => {
                reqinfo.result( {
                    user : user,
                    algo : algo,
                    sig : sig.toString( 'base64' ),
                } );
            } );
        } );
    }

    getMACSecret( as, reqinfo ) {
        const { user } = reqinfo.params();
        const ccm = reqinfo.ccm();

        const svkeys = ccm.iface( SVKEY_FACE );
        svkeys.extKeyInfo( as, this._keyName( reqinfo, user, true ) );

        as.add( ( as, key_info ) => {
            svkeys.exposeKey( as, key_info.id );

            as.add( ( as, sig ) => {
                reqinfo.result( sig.toString( 'base64' ) );
            } );
        } );
    }

    /**
     * Register futoin.auth.stateless interface with Executor
     * @alias StatelessAuthService.register
     * @param {AsyncSteps} as - steps interface
     * @param {Executor} executor - executor instance
     * @param {object} options - implementation defined options
     * @param {Executor} options.scope=main.globalScope
     * @returns {StatelessAuthService} instance
     */
}

module.exports = StatelessAuthService;
