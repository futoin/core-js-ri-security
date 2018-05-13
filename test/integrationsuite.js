'use strict';

const expect = require( 'chai' ).expect;
const $as_test = require( 'futoin-asyncsteps/testcase' );
const $as = require( 'futoin-asyncsteps' );
const ServiceApp = require( '../ServiceApp' );
const AdvancedCCM = require( 'futoin-invoker/AdvancedCCM' );

const {
    KEY_FACE,
} = require( '../lib/main' );
let httpPort = 8081;

module.exports = function( describe, it, databaseConfig ) {
    const ccm = new AdvancedCCM();
    const vars = {
        as: null,
        ccm,
    };
    const STORAGE_PASSWORD = 'e3b694af320229f9b464a358eae063a8';

    before( 'common', $as_test( ( as ) => {
        vars.app = new ServiceApp( as, {
            ccm,
            databaseConfig : databaseConfig,
            publicExecutorOptions : {
                httpAddr: 'localhost',
                httpPort: httpPort++,
            },
            config: {
                domain: 'example.com',
            },
        } );

        const not_expected = function() {
            console.log( arguments );
        };
        vars.app._private_executor.on( 'notExpected', not_expected );
        vars.app._public_executor.on( 'notExpected', not_expected );

        as.add( ( as )=> {
            ccm.iface( KEY_FACE ).unlock( as, Buffer.from( STORAGE_PASSWORD, 'hex' ) );
        } );
    } ) );

    after( 'specific', function( done ) {
        vars.app._public_executor.close( () => {
            vars.app.close();
            done();
        } );
    } );

    beforeEach( 'common', function() {
        vars.as = $as();
    } );

    describe( 'Manage', function() {
        require( './manage_suite' )( describe, it, vars );
    } );
};
