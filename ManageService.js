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

const _merge = require( 'lodash/merge' );

const UUIDTool = require( 'futoin-uuid' );
const BaseService = require( './lib/BaseService' );
const ManageFace = require( './ManageFace' );
const {
    EVTGEN_FACE,
    DB_USERS_TABLE,
} = require( './lib/main' );

const SYM_SELECT_USER = Symbol( 'selectUser' );

/**
 * Manage Service
 */
class ManageService extends BaseService {
    static get IFACE_IMPL() {
        return ManageFace;
    }

    setup( as, reqinfo ) {
        _merge( this._scope.config, reqinfo.params() );
        reqinfo.result( true );
    }

    genConfig( as, _reqinfo ) {
        as.success( this._scope.config );
    }

    _ensureCommon( as, global_id, reqinfo ) {
        const ccm = reqinfo.ccm();
        const db = ccm.db( 'ftnsec' );
        const evt = ccm.iface( EVTGEN_FACE );

        const { config } = this._scope;
        const domain = reqinfo.params().domain;
        const is_local = config.domains.indexOf( domain ) >= 0;

        if ( !config.auth_service ) {
            as.error( 'InternalError', 'AuthService is not enabled' );
        }

        as.repeat( 2, ( as ) => {
            db
                .getPrepared( SYM_SELECT_USER, ( db ) => {
                    const qb = db.select( DB_USERS_TABLE );
                    qb.get( 'uuidb64' );
                    qb.where( 'global_id', qb.param( 'global_id' ) );
                    return qb.prepare();
                } )
                .execute( as, { global_id } );

            as.add( ( as, { rows } ) => {
                if ( rows.length === 1 ) {
                    reqinfo.result( rows[0][0] );
                    as.break();
                }

                const uuidb64 = UUIDTool.genB64();
                const user_info = {
                    uuidb64,
                    global_id,
                    is_local : is_local ? 'Y' : 'N',
                    is_enabled : 'Y',
                };

                const xfer = db.newXfer();
                xfer.insert( DB_USERS_TABLE )
                    .set( user_info )
                    .set( 'created', db.helpers().now() );
                evt.addXferEvent( xfer, 'USER_NEW', user_info );

                as.add(
                    ( as ) => xfer.execute( as ),
                    ( as, err ) => {
                        if ( err === 'Duplicate' ) {
                            as.continue();
                        }
                    }
                );
                as.add( ( as ) => {
                    reqinfo.result( uuidb64 );
                    as.break();
                } );
            } );
        } );
    }

    ensureUser( as, reqinfo ) {
        const p = reqinfo.params();
        const global_id = `${p.user}@${p.domain}`;
        this._ensureCommon( as, global_id, reqinfo );
    }

    ensureService( as, reqinfo ) {
        const p = reqinfo.params();
        const global_id = `${p.user}.${p.domain}`;
        this._ensureCommon( as, global_id, reqinfo );
    }

    /**
     * Register futoin.secvault.keys interface with Executor
     * @alias ManageService.register
     * @param {AsyncSteps} as - steps interface
     * @param {Executor} executor - executor instance
     * @param {object} options - implementation defined options
     * @param {Executor} options.scope=main.globalScope
     * @returns {ManageService} instance
     */
}

module.exports = ManageService;
