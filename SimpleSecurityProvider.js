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

const { SpecTools } = require( 'futoin-invoker' );
const { SecurityProvider } = require( 'futoin-executor' );
const {
    STLS_AUTH_FACE,
    MASTER_AUTH_FACE,
} = require( './lib/main' );
const { reqinfo2source } = require( './lib/util' );

const SYM_SP_SIGNER = Symbol( 'SP-SIGNER' );

/**
 * Simple passthru FTN8 security provider for Executor.
 *
 * NOTE: it's suitable for lightweight services without own SecVault.
 */
class SimpleSecurityProvider extends SecurityProvider {
    checkAuth( as, reqinfo, reqmsg, sec ) {
        // FTN8.2: Master MAC
        if ( sec[ 0 ] === '-mmac' ) {
            this._checkMasterMAC( as, reqinfo, reqmsg, {
                msid: sec[1],
                algo: sec[2],
                kds: sec[3],
                prm: sec[4],
                sig: sec[5],
            } );
        // FTN8.1: Stateless MAC
        } else if ( sec[ 0 ] === '-smac' ) {
            this._checkStatelessMAC( as, reqinfo, reqmsg, {
                user: sec[1],
                algo: sec[2],
                sig: sec[3],
            } );
        // FTN8.1: Clear secret
        } else if ( sec.length == 2 ) {
            this._checkStatelessClear( as, reqinfo, {
                user: sec[0],
                secret: sec[1],
            } );
        }
    }

    signAuto( as, reqinfo, rspmsg ) {
        const sp_signer = reqinfo.info[SYM_SP_SIGNER];

        if ( sp_signer ) {
            sp_signer( as, reqinfo, rspmsg );
            return true;
        }

        return false;
    }

    isSigned( reqinfo ) {
        return ( SYM_SP_SIGNER in reqinfo.info );
    }

    _getSource( reqinfo ) {
        return reqinfo2source( reqinfo );
    }

    _checkStatelessClear( as, reqinfo, sec ) {
        const auth_face = reqinfo.ccm().iface( STLS_AUTH_FACE );
        const source = this._getSource( reqinfo );

        auth_face.call( as, 'checkClear', { sec, source } );
        as.add( ( as, auth_info ) => {
            this._setUser( as, reqinfo, 'SafeOps', auth_info );
        } );
    }

    _checkStatelessMAC( as, reqinfo, rawreq, sec ) {
        const auth_face = reqinfo.ccm().iface( STLS_AUTH_FACE );
        const source = this._getSource( reqinfo );
        const base = SpecTools.macBase( rawreq );

        auth_face.call( as, 'checkMAC', { base, sec, source } );
        as.add( ( as, auth_info ) => {
            this._setUser( as, reqinfo, 'PrivilegedOps', auth_info );
            reqinfo.info[SYM_SP_SIGNER] = ( as, reqinfo, rspmsg ) => {
                this._signStatelessMAC( as, reqinfo, rspmsg, sec );
            };
        } );
    }

    _signStatelessMAC( as, reqinfo, rspmsg, reqsec ) {
        const auth_face = reqinfo.ccm().iface( STLS_AUTH_FACE );
        const base = SpecTools.macBase( rspmsg );

        auth_face.call( as, 'genMAC', { base, reqsec } );
        as.add( ( as, sig ) => {
            rspmsg.sec = sig;
        } );
    }

    _checkMasterMAC( as, reqinfo, rawreq, sec ) {
        const auth_face = reqinfo.ccm().iface( MASTER_AUTH_FACE );
        const source = this._getSource( reqinfo );
        const base = SpecTools.macBase( rawreq );

        auth_face.call( as, 'checkMAC', { base, sec, source } );
        as.add( ( as, auth_info ) => {
            this._setUser( as, reqinfo, 'ExceptionalOps', auth_info );
            reqinfo.info[SYM_SP_SIGNER] = ( as, reqinfo, rspmsg ) => {
                this._signMasterMAC( as, reqinfo, rspmsg, sec );
            };
        } );
    }

    _signMasterMAC( as, reqinfo, rspmsg, reqsec ) {
        const auth_face = reqinfo.ccm().iface( MASTER_AUTH_FACE );
        const base = SpecTools.macBase( rspmsg );

        auth_face.call( as, 'genMAC', { base, reqsec } );
        as.add( ( as, sig ) => {
            rspmsg.sec = sig;
        } );
    }
}

module.exports = SimpleSecurityProvider;
