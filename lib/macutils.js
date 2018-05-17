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

exports.parseMode = ( mode ) => {
    let type;
    let hash;

    switch ( mode ) {
    case 'HMAC-MD5':
    case 'HMD5':
        type = 'HMAC';
        hash = 'MD5';
        break;
    case 'HMAC-GOST3411-256':
    case 'HG256':
        type = 'HMAC';
        hash = 'md_gost12_256';
        break;
    case 'HMAC-GOST3411-512':
    case 'HG512':
        type = 'HMAC';
        hash = 'md_gost12_512';
        break;
    case 'HMAC-SHA-224':
    case 'HS224':
        type = 'HMAC';
        hash = 'SHA224';
        break;
    case 'HMAC-SHA-256':
    case 'HS256':
        type = 'HMAC';
        hash = 'SHA256';
        break;
    case 'HMAC-SHA-384':
    case 'HS384':
        type = 'HMAC';
        hash = 'SHA384';
        break;
    case 'HMAC-SHA-512':
    case 'HS512':
        type = 'HMAC';
        hash = 'SHA512';
        break;
    case 'KMAC-128':
        type = 'KMAC';
        hash = '128';
        break;
    case 'KMAC-256':
        type = 'KMAC';
        hash = '256';
        break;
    default:
        throw new Error( `Unknown hash type: ${hash}` );
    }

    return { type, hash };
};
