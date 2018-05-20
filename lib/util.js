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

const assert = require( 'assert' );
const Errors = require( 'futoin-asyncsteps/Errors' );

const {
    MANAGE_FACE,
    SVKEY_FACE,
} = require( './main' );

module.exports = new class {
    checkUser( as, ccm, user, source = null ) {
        as.isAsyncSteps();
        assert( user );

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

            if ( source ) {
                // TODO: check fingerprints
            }

            as.success( info );
        } );
    }

    parseMACAlgo( as, algo ) {
        let macf;
        let hash;

        switch ( algo ) {
        case 'HMAC-MD5':
        case 'HMD5':
            macf = 'HMAC';
            hash = 'MD5';
            break;
        case 'HMAC-GOST3411-256':
        case 'HG256':
            macf = 'HMAC';
            hash = 'md_gost12_256';
            break;
        case 'HMAC-GOST3411-512':
        case 'HG512':
            macf = 'HMAC';
            hash = 'md_gost12_512';
            break;
        case 'HMAC-SHA-224':
        case 'HS224':
            macf = 'HMAC';
            hash = 'SHA224';
            break;
        case 'HMAC-SHA-256':
        case 'HS256':
            macf = 'HMAC';
            hash = 'SHA256';
            break;
        case 'HMAC-SHA-384':
        case 'HS384':
            macf = 'HMAC';
            hash = 'SHA384';
            break;
        case 'HMAC-SHA-512':
        case 'HS512':
            macf = 'HMAC';
            hash = 'SHA512';
            break;
        case 'KMAC-128':
            macf = 'KMAC';
            hash = '128';
            break;
        case 'KMAC-256':
            macf = 'KMAC';
            hash = '256';
            break;
        default:
            as.error( Errors.InvokerError, `Unknown hash type: ${algo}` );
        }

        return { macf, hash };
    }

    parseKDS( as, kds ) {
        let kdf;
        let kdf_hash;

        switch ( kds ) {
        case 'HKDF256':
            kdf = 'HKDF';
            kdf_hash = 'SHA-256';
            break;

        case 'HKDF512':
            kdf = 'HKDF';
            kdf_hash = 'SHA-512';
            break;

        default:
            as.error( Errors.InvokerError, `Unknown KDS: ${kds}` );
        }

        return { kdf, kdf_hash };
    }

    purpose2usage( as, purpose ) {
        switch ( purpose ) {
        case 'MAC': return [ 'sign', 'shared', 'temp' ];
        case 'ENC': return [ 'encrypt', 'shared', 'temp' ];
        case 'EXPOSED': return [ 'encrypt', 'sign', 'shared', 'temp' ];
        default: as.error( Errors.Invoker, `Unknown key purpose: ${purpose}` );
        }
    }

    ensureDerivedKey( as, ccm, purpose, { msid, type, kds, salt, prm, forbid_derive=false } ) {
        assert( salt, 'Empty salt' );
        assert( msid, 'Empty Master Secret ID' );
        assert( kds, 'Empty Key Derivation Strategy' );
        assert( type, 'Empty Key type' );

        const { kdf, kdf_hash } = this.parseKDS( as, kds );
        const kdf_salt = `${salt}:${purpose}`;

        const svkey = ccm.iface( SVKEY_FACE );

        const drv_ext_id = `${msid}:DRV:${kds}:${type}:${kdf_salt}:${prm}`;

        // Try to get already derived key
        as.add(
            ( as ) => {
                svkey.extKeyInfo( as, drv_ext_id );

                // Fast path result
                as.add( ( as, key_info ) => {
                    const { local_id, global_id } = key_info.params;
                    assert( local_id );
                    assert( global_id );

                    const auth_info = { local_id, global_id };
                    as.success( { auth_info, dsid: key_info.id } );
                } );
            },
            ( as, err ) => {
                if ( ( err !== 'UnknownKeyID' ) || forbid_derive ) {
                    return;
                }

                // Check if master key exists
                svkey.keyInfo( as, msid );

                as.add( ( as, mkey_info ) => {
                    const { local_id, bits } = mkey_info.params;
                    assert( local_id );

                    // ensure user is enabled
                    this.checkUser( as, ccm, local_id );

                    as.add( ( as, { global_id, ds_max } ) => {
                        // NOTE: make sure to use actual Global ID
                        assert( global_id );

                        // Check if too many derived keys
                        svkey.listKeys( as, `${msid}:DRV:` );
                        as.add( ( as, keys ) => {
                            if ( ( keys.length + 1 ) >= ds_max ) {
                                as.error( 'SecurityError', 'Too many derived keys' );
                            }
                        } );

                        // Derive key
                        svkey.deriveKey(
                            as,
                            drv_ext_id,
                            this.purpose2usage( as, purpose ),
                            type,
                            {
                                bits,
                                local_id,
                                global_id,
                            },
                            msid,
                            kdf,
                            kdf_hash,
                            Buffer.from( kdf_salt ),
                            {
                                info: prm,
                            }
                        );

                        // Slow path result
                        as.add( ( as, dsid ) => {
                            const auth_info = { local_id, global_id };
                            as.success( { auth_info, dsid } );
                        } );
                    } );
                } );
            }
        );
    }

    encryptKey( as, ccm, { key_id, emode }, { salt, msid, type, kds, prm } ) {
        this.ensureDerivedKey(
            as, ccm, 'ENC',
            { salt, msid, type, kds, prm }
        );

        as.add( ( as, tmp ) => {
            const dsid = tmp.dsid;
            const svkey = ccm.iface( SVKEY_FACE );
            svkey.encryptedKey(
                as,
                key_id,
                dsid,
                emode
            );
            as.add( ( as, ekey ) => {
                svkey.wipeKey( as, dsid );
                as.successStep( ekey );
            } );
        } );
    }

    injectEncryptedMACKey(
        as, ccm,
        { ext_id, emode, ekey, local_id, global_id },
        { salt, msid, type, kds, prm }
    ) {
        this.ensureDerivedKey(
            as, ccm, 'ENC',
            { salt, msid, type, kds, prm }
        );

        as.add( ( as, tmp ) => {
            const dsid = tmp.dsid;
            const svkey = ccm.iface( SVKEY_FACE );
            svkey.injectEncryptedKey(
                as,
                ext_id,
                this.purpose2usage( as, 'MAC' ),
                'HMAC',
                { local_id, global_id },
                ekey,
                dsid,
                emode
            );
            as.add( ( as, ekey ) => {
                svkey.wipeKey( as, dsid );
                as.successStep( ekey );
            } );
        } );
    }
};
