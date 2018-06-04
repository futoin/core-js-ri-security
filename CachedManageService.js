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

const $asyncevent = require( 'futoin-asyncevent' );
const ReliableReceiver = require( 'futoin-eventstream/ReliableReceiver' );

const ManageService = require( './ManageService' );
const lruCache = require( 'lru-cache' );

const USER_CACHE = Symbol( 'USER_CACHE' );

const DEF_CACHE_SIZE = 10240;
const DEF_TTL_MS = 600e3;

/**
 * FTN8: Cached Manage Service
 */
class CachedManageService extends ManageService {
    /**
     * C-tor
     * @param {object} scope - scope of related services
     * @param {object} options - passed to superclass c-tor
     * @param {integer} options.scope=main.globalScope - scope state
     */
    constructor( scope, options ) {
        super( scope, options );

        $asyncevent( this, [
            'workerError',
        ] );

        const {
            cacheSize = DEF_CACHE_SIZE,
            ttlMs = DEF_TTL_MS,
            ccm = null,
            evtpushExecutor = null,
        } = options;

        this[USER_CACHE] = new lruCache( {
            max: cacheSize,
            maxAge: ttlMs,
        } );

        if ( !ccm ) {
            throw new Error( 'Missing "ccm" option' );
        }

        if ( !evtpushExecutor ) {
            throw new Error( 'Missing "evtpushExecutor" option' );
        }

        //---
        const that = this;
        let receiver = new class extends ReliableReceiver {
            constructor() {
                super( ccm );
            }

            _onEvents( as, events ) {
                for ( let e of events ) {
                    switch ( e.type ) {
                    case 'USR_MOD':
                        that._onUserInfoUpdate( e.data );
                        break;
                    }
                }
            }
        };

        receiver.on( 'workerError', ( ...args ) => this.emit( 'workerError', ...args ) );
        receiver.on( 'receiverError', ( ...args ) => this.emit( 'workerError', ...args ) );

        receiver.start( evtpushExecutor, null, { want: [ 'USR_MOD' ] } );

        const close = () => receiver.stop();
        evtpushExecutor.once( 'close', close );
        ccm.once( 'close', close );
    }

    _userInfoCommon( as, reqinfo ) {
        const local_id = reqinfo.params().local_id;

        const ui = this[USER_CACHE].get( local_id );

        if ( ui ) {
            as.successStep( Object.assign( {}, ui ) );
        } else {
            super._userInfoCommon( as, reqinfo );
            as.add( ( as, res ) => {
                this[USER_CACHE].set( local_id, res );
                as.success( Object.assign( {}, res ) );
            } );
        }
    }

    _onUserInfoUpdate( evt_data ) {
        const ui = this[USER_CACHE].peek( evt_data.local_id );

        if ( !ui ) {
            return;
        }

        const { is_enabled, ms_max, ds_max } = evt_data;

        if ( is_enabled !== undefined ) {
            ui.is_enabled = is_enabled;
        }

        if ( ms_max !== undefined ) {
            ui.ms_max = ms_max;
        }

        if ( ds_max !== undefined ) {
            ui.ds_max = ds_max;
        }
    }
}

module.exports = CachedManageService;
