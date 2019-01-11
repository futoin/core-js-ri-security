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

const AdvancedCCM = require( 'futoin-invoker/AdvancedCCM' );
const NodeExecutor = require( 'futoin-executor/NodeExecutor' );
const Executor = require( 'futoin-executor/Executor' );
const DBAutoConfig = require( 'futoin-database/AutoConfig' );
const _merge = require( 'lodash/merge' );

const SQLStorage = require( 'futoin-secvault/lib/storage/SQLStorage' );
const CachedStorageWrapper = require( 'futoin-secvault/lib/storage/CachedStorageWrapper' );
const KeyFace = require( 'futoin-secvault/KeyFace' );
const KeyService = require( 'futoin-secvault/KeyService' );
const DataFace = require( 'futoin-secvault/DataFace' );
const DataService = require( 'futoin-secvault/DataService' );

const DBGenFace = require( 'futoin-eventstream/DBGenFace' );
const DBGenService = require( 'futoin-eventstream/DBGenService' );
const PushFace = require( 'futoin-eventstream/PushFace' );
const DBPushService = require( 'futoin-eventstream/DBPushService' );

const {
    MANAGE_FACE,
    STLS_AUTH_FACE,
    STLS_MANAGE_FACE,
    MASTER_AUTH_FACE,
    MASTER_AUTOREG_FACE,
    MASTER_MANAGE_FACE,
    SVKEY_FACE,
    SVDATA_FACE,
    EVTGEN_FACE,
    EVTPUSH_FACE,
    scopeTemplate,
} = require( './lib/main' );

const ManageFace = require( './ManageFace' );
const CachedManageService = require( './CachedManageService' );

const StatelessManageFace = require( './StatelessManageFace' );
const StatelessManageService = require( './StatelessManageService' );
const StatelessAuthFace = require( './StatelessAuthFace' );
const StatelessAuthService = require( './StatelessAuthService' );

const MasterManageFace = require( './MasterManageFace' );
const MasterManageService = require( './MasterManageService' );
const MasterAuthFace = require( './MasterAuthFace' );
const MasterAuthService = require( './MasterAuthService' );
const MasterAutoregFace = require( './MasterAutoregFace' );
const MasterAutoregService = require( './MasterAutoregService' );

const SimpleSecurityProvider = require( './SimpleSecurityProvider' );

/**
 * All-in-one AuthService initialization
 */
class ServiceApp {
    /**
     * C-tor
     *
     * @param {AsyncSteps} as - AsyncSteps interface
     * @param {object} options={} - options
     * @param {AdvancedCCM} [options.ccm] - external CCM instance
     * @param {Executor} [options.publicExecutor] - external public executor instance
     * @param {Executor} [options.privateExecutor] - external private executor instance
     * @param {string} [options.storagePassword] - Base64 encoded KEK for storage
     * @param {object} [options.config] - config overrides for MasterService
     * @param {object} [options.ccmOptions] - auto-CCM options
     * @param {callable} [options.notExpectedHandler] - 'notExpected' error handler
     * @param {object} [options.privateExecutorOptions] - private auto-Executor options
     * @param {object} [options.publicExecutorOptions] - public auto-Executor options
     * @param {object} [options.evtOptions] - eventstream options
     * @param {object} [options.secVaultOptions] - secure vault options
     * @param {object} [options.securityOptions] - security interface options
     */
    constructor( as, options = {} ) {
        let {
            ccm,
            publicExecutor,
            privateExecutor,
            notExpectedHandler,
            storagePassword,
            secVaultOptions,
            securityOptions,
        } = options;

        // minimize exposure
        options.storagePassword = null;

        // Scope setup
        const scope = _merge( {}, scopeTemplate );
        Object.seal( scope );
        Object.seal( scope.config );

        // Config from template
        const config = Object.assign( {}, scopeTemplate.config );
        Object.seal( config );
        _merge( config, options.config || {} );

        // Init of standard FutoIn components
        if ( !ccm ) {
            ccm = new AdvancedCCM( options.ccmOptions );
        }

        ccm.once( 'close', () => {
            this._ccm = null;
            this.close();
        } );

        if ( !privateExecutor ) {
            privateExecutor = new Executor( ccm, options.privateExecutorOptions );
        }

        if ( !publicExecutor ) {
            const securityProvider = new SimpleSecurityProvider();
            const opts = Object.assign(
                { securityProvider },
                options.publicExecutorOptions
            );
            publicExecutor = new NodeExecutor( ccm, opts );
        }

        if ( !notExpectedHandler ) {
            notExpectedHandler = function() {
                // eslint-disable-next-line no-console
                console.log( arguments );
            };
        }

        privateExecutor.on( 'notExpected', notExpectedHandler );
        publicExecutor.on( 'notExpected', notExpectedHandler );

        this._scope = scope;
        this._ccm = ccm;
        this._private_executor = privateExecutor;
        this._public_executor = publicExecutor;

        // Common database
        DBAutoConfig( as, ccm, {
            ftnsec: {},
        }, options.databaseConfig );
        ccm.alias( '#db.ftnsec', '#db.secvault' );
        ccm.alias( '#db.ftnsec', '#db.evt' );

        as.add( ( as ) => {
            // EvtStream
            DBGenService.register( as, privateExecutor, options.evtOptions );
            DBGenFace.register( as, ccm, EVTGEN_FACE, privateExecutor );
            DBPushService.register( as, privateExecutor, options.evtOptions );
            PushFace.register( as, ccm, EVTPUSH_FACE, privateExecutor );
        } );

        as.add( ( as ) => {
            // SecVault
            ccm.alias( EVTGEN_FACE, '#secvault.evtgen' );
            ccm.alias( EVTPUSH_FACE, '#secvault.evtpush' );
            const sv_storage = new SQLStorage( ccm, secVaultOptions );
            const cached_sv_storage = new CachedStorageWrapper(
                ccm, sv_storage,
                Object.assign( { evtpushExecutor: privateExecutor }, secVaultOptions )
            );
            KeyService.register( as, privateExecutor, cached_sv_storage, secVaultOptions );
            KeyFace.register( as, ccm, SVKEY_FACE, privateExecutor );
            DataService.register( as, privateExecutor, cached_sv_storage, secVaultOptions );
            DataFace.register( as, ccm, SVDATA_FACE, privateExecutor );
        } );

        as.add( ( as ) => {
            // Init of FutoIn Security services
            CachedManageService.register( as, privateExecutor, scope, Object.assign( {
                ccm,
                evtpushExecutor: privateExecutor,
            }, securityOptions ) );
            ManageFace.register( as, ccm, MANAGE_FACE, privateExecutor, securityOptions );

            StatelessManageService.register( as, privateExecutor, scope, securityOptions );
            StatelessManageFace.register( as, ccm, STLS_MANAGE_FACE, privateExecutor, securityOptions );
            StatelessAuthService.register( as, publicExecutor, scope, securityOptions );
            StatelessAuthFace.register( as, ccm, STLS_AUTH_FACE, publicExecutor, securityOptions );

            MasterManageService.register( as, privateExecutor, scope, securityOptions );
            MasterManageFace.register( as, ccm, MASTER_MANAGE_FACE, privateExecutor, securityOptions );
            MasterAuthService.register( as, publicExecutor, scope, securityOptions );
            MasterAuthFace.register( as, ccm, MASTER_AUTH_FACE, publicExecutor, securityOptions );
            MasterAutoregService.register( as, publicExecutor, scope, securityOptions );
            MasterAutoregFace.register( as, ccm, MASTER_AUTOREG_FACE, publicExecutor, securityOptions );
        } );

        as.add( ( as ) => {
            ccm.iface( MANAGE_FACE ).call( as, 'setup', config );

            if ( storagePassword ) {
                ccm.iface( SVKEY_FACE ).unlock( as, Buffer.from( storagePassword, 'hex' ) );
            }
        } );
    }

    /**
     * CCM instance accessor
     * @returns {AdvancedCCM} instance
     */
    ccm() {
        return this._ccm;
    }

    /**
     * Executor instance accessor
     * @returns {Executor} instance
     */
    executor() {
        return this._public_executor;
    }

    /**
     * Shutdown of app and related instances
     * @param {callable} [done] - done callback
     */
    close( done=null ) {
        if ( this._ccm ) {
            this._ccm.close();
            this._ccm = null;

            this._public_executor.close( done );
        }

        this._private_executor = null;
        this._public_executor = null;
    }
}

module.exports = ServiceApp;
