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

const moment = require( 'moment' );

const UUIDTool = require( 'futoin-uuid' );
const Errors = require( 'futoin-asyncsteps/Errors' );
const BaseService = require( './lib/BaseService' );
const ManageFace = require( './ManageFace' );
const {
    EVTGEN_FACE,
    DB_USERS_TABLE,
} = require( './lib/main' );

const SYM_SELECT_USER = Symbol( 'selectUser' );
const SYM_SELECT_USER_INFO = Symbol( 'selectUserInfo' );

/**
 * FTN8: main Manage Service
 */
class ManageService extends BaseService {
    static get IFACE_IMPL() {
        return ManageFace;
    }

    setup( as, reqinfo ) {
        const ccm = reqinfo.ccm();
        const scope = this._scope;
        const { config } = scope;
        const params = reqinfo.params();

        for ( let k of Object.keys( params ) ) {
            const v = params[k];

            if ( v !== null ) {
                config[k] = v;
            }
        }

        const domain2service = {};

        if ( config.auth_service ) {
            as.forEach( config.domains, ( as, _, global_id ) => {
                this._ensureNoChecks( as, {
                    ccm,
                    global_id,
                    is_local: true,
                    is_service: true,
                } );

                as.add( ( as, local_id ) => {
                    domain2service[global_id] = local_id;
                } );
            } );
            as.add( ( as ) => {
                scope.system_local_id = domain2service[config.domains[0]];
            } );
        }

        as.add( ( as ) => {
            // atomic change
            Object.freeze( domain2service );
            scope.domain2service = domain2service;

            reqinfo.result( true );
        } );
    }

    genConfig( as, _reqinfo ) {
        as.success( this._scope.config );
    }

    _ensureNoChecks( as, { ccm, global_id, is_local, is_service } ) {
        const db = ccm.db( 'ftnsec' );
        const evt = ccm.iface( EVTGEN_FACE );
        let local_id;

        as.repeat( 2, ( as ) => {
            db
                .getPrepared( SYM_SELECT_USER, ( db ) => {
                    const qb = db.select( DB_USERS_TABLE );
                    qb.get( 'local_id' );
                    qb.where( 'global_id', qb.param( 'global_id' ) );
                    return qb.prepare();
                } )
                .execute( as, { global_id } );

            as.add( ( as, { rows } ) => {
                if ( rows.length === 1 ) {
                    local_id = rows[0][0];
                    as.break();
                }

                local_id = UUIDTool.genB64();
                const user_info = {
                    local_id,
                    global_id,
                    is_local : is_local ? 'Y' : 'N',
                    is_enabled : 'Y',
                    is_service : is_service ? 'Y' : 'N',
                };
                const q_now = db.helpers().now();

                const xfer = db.newXfer();
                xfer.insert( DB_USERS_TABLE )
                    .set( user_info )
                    .set( 'created', q_now )
                    .set( 'updated', q_now );
                evt.addXferEvent( xfer, 'USR_NEW', user_info );

                as.add(
                    ( as ) => {
                        xfer.execute( as );
                        as.add( ( as ) => as.break() );
                    },
                    ( as, err ) => {
                        if ( err === 'Duplicate' ) {
                            as.continue();
                        }
                    }
                );
            } );
        } );
        as.add( ( as ) => as.success( local_id ) );
    }

    _ensureCommon( as, global_id, reqinfo, is_service ) {
        const { config } = this._scope;

        if ( !config.auth_service ) {
            as.error( Errors.InternalError, 'AuthService is not enabled' );
        }

        //---
        const { domain } = reqinfo.params();
        const is_local = config.domains.indexOf( domain ) >= 0;

        //---
        const ccm = reqinfo.ccm();
        this._ensureNoChecks( as, { ccm, global_id, is_local, is_service } );
        as.add( ( as, local_id ) => reqinfo.result( local_id ) );
    }

    ensureUser( as, reqinfo ) {
        const p = reqinfo.params();
        const global_id = `${p.user}@${p.domain}`;
        this._ensureCommon( as, global_id, reqinfo, false );
    }

    ensureService( as, reqinfo ) {
        const p = reqinfo.params();
        const global_id = `${p.hostname}.${p.domain}`;
        this._ensureCommon( as, global_id, reqinfo, true );
    }

    _userInfoCommon( as, reqinfo ) {
        const db = reqinfo.ccm().db( 'ftnsec' );
        const local_id = reqinfo.params().local_id;

        db
            .getPrepared( SYM_SELECT_USER_INFO, ( db ) => {
                const qb = db.select( DB_USERS_TABLE );
                qb.get( [
                    'local_id',
                    'global_id',
                    'is_enabled',
                    'is_local',
                    'is_service',
                    'ms_max',
                    'ds_max',
                    'created',
                    'updated',
                ] );
                qb.where( 'local_id', qb.param( 'local_id' ) );
                return qb.prepare();
            } )
            .executeAssoc( as, { local_id } );

        as.add( ( as, rows ) => {
            if ( rows.length !== 1 ) {
                as.error( 'UnknownUser', `UserID: ${local_id}` );
            }

            as.success( rows[0] );
        } );
    }

    _onUserInfoUpdate( _evt_data ) {
        // pass
    }

    getUserInfo( as, reqinfo ) {
        // TODO: caching
        this._userInfoCommon( as, reqinfo );

        as.add( ( as, r ) => {
            const { config } = this._scope;

            r.is_enabled = ( r.is_enabled === 'Y' );
            r.is_local = ( r.is_local === 'Y' );
            r.is_service = ( r.is_service === 'Y' );
            r.ms_max = r.ms_max ||
                ( r.is_service
                    ? config.def_service_ms_max
                    : config.def_user_ms_max );
            r.ds_max = r.ds_max || r.ms_max;
            r.created = moment.utc( r.created ).format();
            r.updated = moment.utc( r.updated ).format();
            reqinfo.result( r );
        } );
    }

    setUserInfo( as, reqinfo ) {
        this._userInfoCommon( as, reqinfo );

        as.add( ( as, r ) => {
            const params = reqinfo.params();
            const { local_id, is_enabled, ms_max, ds_max } = params;
            const { config } = this._scope;

            const ccm = reqinfo.ccm();
            const db = ccm.db( 'ftnsec' );
            const evt = ccm.iface( EVTGEN_FACE );

            //---
            const xfer = db.newXfer();
            const uq = xfer.update( DB_USERS_TABLE )
                .set( 'updated', db.helpers().now() )
                .where( 'local_id', local_id );
            const changes = {};

            if ( is_enabled !== null ) {
                changes.is_enabled = is_enabled ? 'Y' : 'N';
            }

            if ( ms_max !== null ) {
                if ( ( ( r.is_service === 'Y' ) &&
                       ( ms_max === config.def_service_ms_max ) ) ||
                     ( ( r.is_service === 'N' ) &&
                       ( ms_max === config.def_user_ms_max ) )
                ) {
                    changes.ms_max = null;
                } else {
                    changes.ms_max = ms_max;
                }
            }

            if ( ds_max !== null ) {
                if ( ds_max === ms_max ) {
                    changes.ds_max = null;
                } else {
                    changes.ds_max = ds_max;
                }
            }

            uq.set( changes );

            const evt_data = Object.assign( { local_id }, changes );
            evt.addXferEvent( xfer, 'USR_MOD', evt_data );
            xfer.execute( as );
            //---
            as.add( ( as ) => {
                this._onUserInfoUpdate( evt_data );
                reqinfo.result( true );
            } );
        } );
    }

    /**
     * Register futoin.auth.manage interface with Executor
     * @alias ManageService.register
     * @param {AsyncSteps} as - steps interface
     * @param {Executor} executor - executor instance
     * @param {object} options - implementation defined options
     * @param {Executor} options.scope=main.globalScope
     * @returns {ManageService} instance
     */
}

module.exports = ManageService;
