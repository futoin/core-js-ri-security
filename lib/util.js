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

const checkUser = exports.checkUser = ( as, ccm, user, source = null ) => {
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
};

const parseMACAlgo = exports.parseMACAlgo = ( as, algo ) => {
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
};

const parseKDS = exports.parseKDS = ( as, kds ) => {
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
};

exports.ensureDerivedKey = ( as, ccm, purpose, global_id, { msid, algo, kds, prm } ) => {
    assert( global_id, 'Empty global ID' );
    assert( msid, 'Empty Master Secret ID' );
    assert( kds, 'Empty Key Derivation Strategy' );
    assert( algo, 'Empty KDS algorithm' );

    const { kdf, kdf_hash } = parseKDS( kds );
    const kdf_salt = `${global_id}:${purpose}`;
    const { macf, hash } = parseMACAlgo( as, algo );

    const svkey = ccm.iface( SVKEY_FACE );

    const drv_ext_id = `${msid}:DRV:${kds}:${macf}:${kdf_salt}:${prm}`;

    // Try to get already derived key
    as.add(
        ( as ) => {
            svkey.extKeyInfo( as, drv_ext_id );

            // Fast path result
            as.add( ( as, key_info ) => {
                const { local_id, global_id } = key_info.params;
                const auth_info = { local_id, global_id };
                as.success( { auth_info, hash, dsid: key_info.id } );
            } );
        },
        ( as, err ) => {
            if ( err !== 'UnknownKeyID' ) {
                return;
            }

            // Check if master key exists
            svkey.keyInfo( as, msid );

            as.add( ( as, mkey_info ) => {
                const { local_id, bits } = mkey_info.params;

                // ensure user is enabled
                checkUser( as, local_id );

                as.add( ( as, { global_id, ds_max } ) => {
                    // Check if too many derived keys
                    svkey.listKeys( as, `${msid}:DRV:` );
                    as.add( ( as, keys ) => {
                        if ( ( keys.length + 1 ) >= ds_max ) {
                            as.error( 'SecurityError', 'Too many derived keys' );
                        }
                    } );

                    // Derive key
                    const usage = ( purpose === 'ENC' )
                        ? [ 'encrypt', 'temp' ]
                        : [ 'sign', 'temp' ];

                    svkey.deriveKey(
                        as,
                        drv_ext_id,
                        usage,
                        macf,
                        bits,
                        msid,
                        kdf,
                        kdf_hash,
                        Buffer.from( kdf_salt ),
                        {
                            info: prm,
                            local_id,
                            global_id,
                        }
                    );

                    // Slow path result
                    as.add( ( as, dsid ) => {
                        const auth_info = { local_id, global_id };
                        as.success( { auth_info, hash, dsid } );
                    } );
                } );
            } );
        }
    );
};
