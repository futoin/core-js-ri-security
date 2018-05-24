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

const { MasterAuth, SpecTools } = require( 'futoin-invoker' );
const { parseMACAlgo, parseKDS } = require( './lib/util' );
const moment = require( 'moment' );
const url = require( 'url' );
const hkdf = require( 'futoin-hkdf' );

/**
 * MasterAuth implementation for AdvancedCCM with static Master Key
 *
 * NOTE: this implementation rotates only derived keys
 */
class StaticMasterAuth extends MasterAuth {
    /**
     * C-tor
     *
     * @param {object} options - Options
     * @param {string} keyId - master key ID
     * @param {string} keyData - master key data in Base64
     * @param {string} [paramFormat=YYYYMMDD] - format for derivation parameter
     * @param {string} [kds=HKDF256] - key derivation strategy
     * @param {string} [macAlgo=HS256] - MAC algorithm
     */
    constructor( {
        keyId, keyData,
        paramFormat = 'YYYYMMDD',
        kds='HKDF256',
        macAlgo='HS256',
    } ) {
        super();

        if ( !keyId ) {
            throw new Error( 'Missing keyId for StaticMasterAuth' );
        }

        if ( !keyData ) {
            throw new Error( 'Missing keyData for StaticMasterAuth' );
        }

        this._key_id = keyId;
        this._key_data = Buffer.from( keyData, 'base64' );
        this._prm_format = paramFormat;
        this._last_prm = {};
        this._cached_drv = {};

        //---
        const fake_as = {
            error: ( e, ei ) => {
                throw new Error( `${e}: ${ei}` );
            },
        };

        const { kdf, kdf_hash } = parseKDS( fake_as, kds );

        if ( kdf !== 'HKDF' ) {
            throw new Error( 'Only HKDF is supported in StaticMasterAuth' );
        }

        this._kds = kds;
        this._kdf_hash = kdf_hash;
        this._kdf_size = this._key_data.length;

        //---
        const { macf, hash } = parseMACAlgo( fake_as, macAlgo );

        if ( macf !== 'HMAC' ) {
            throw new Error( 'Only HMAC is supported in StaticMasterAuth' );
        }

        this._mac_algo = macAlgo;
        this._mac_hash = hash;
    }

    signMessage( ctx, req ) {
        const sig = this.genMAC( ctx, req ).toString( 'base64' );
        req.sec = `-mmac:${this._key_id}:${this._mac_algo}:${this._kds}:${this._last_prm}:${sig}`;
    }

    genMAC( ctx, rsp ) {
        // Identify global ID of target
        let global_id = ctx.options.serviceGlobalId;

        if ( !global_id ) {
            global_id = url.parse( ctx.endpoint ).hostname;
            ctx.options.serviceGlobalId = global_id;
        }

        // Process param & cache
        const prm = moment.utc().format( this._prm_format );

        if ( ( this._last_prm !== prm ) || !this._cached_drv[global_id] ) {
            const drv = hkdf( this._key_data, this._kdf_size, {
                salt: Buffer.from( `${global_id}:MAC` ),
                info: prm,
                hash: this._kdf_hash,
            } );
            this._cached_drv[global_id] = drv;
            this._last_prm = prm;
        }

        // Actual get
        return SpecTools.genHMACRaw(
            this._mac_hash, this._cached_drv[global_id], rsp );
    }
}

module.exports = StaticMasterAuth;
