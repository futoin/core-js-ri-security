'use strict';

const expect = require( 'chai' ).expect;
const $as_test = require( 'futoin-asyncsteps/testcase' );
const $as = require( 'futoin-asyncsteps' );
const ServiceApp = require( '../ServiceApp' );
const SpecTools = require( 'futoin-invoker/SpecTools' );

const {
    SVKEY_FACE,
} = require( '../lib/main' );
let httpPort = 8081;

module.exports = function( describe, it, databaseConfig ) {
    const vars = {
        app: null,
        ccm: null,
    };
    const STORAGE_PASSWORD = 'e3b694af320229f9b464a358eae063a8';

    before( 'common', $as_test( ( as ) => {
        vars.httpPort = httpPort;
        vars.app = new ServiceApp( as, {
            databaseConfig : databaseConfig,
            publicExecutorOptions : {
                httpAddr: 'localhost',
                httpPort: httpPort++,
                secureChannel: true,
            },
            config: {
                domains: [
                    'example.com',
                ],
            },
            storagePassword: STORAGE_PASSWORD,
        } );
        vars.ccm = vars.app.ccm();
        vars.ccm.limitZone( 'default', { rate: 0xFFFF } );


        SpecTools.on( 'error', function() {
            // console.log( arguments );
        } );
    } ) );

    after( 'specific', function() {
        if ( vars.app ) {
            vars.app.close();
        }
    } );

    describe( 'Manage', function() {
        require( './manage_suite' )( { describe, it, vars } );
    } );

    describe( 'Stateless', function() {
        require( './stateless_suite' )( { describe, it, vars } );
    } );

    describe( 'Master', function() {
        require( './master_suite' )( { describe, it, vars } );
    } );
};
