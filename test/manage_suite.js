'use strict';

const expect = require( 'chai' ).expect;
const $as_test = require( 'futoin-asyncsteps/testcase' );
const {
    MANAGE_FACE,
} = require( '../lib/main' );

module.exports = function( { it, vars } ) {
    let ccm;

    before( 'manage', () => {
        ccm = vars.ccm;
    } );

    it ( 'get config', $as_test( ( as ) => {
        ccm.iface( MANAGE_FACE ).genConfig( as );
        as.add( ( as, res ) => expect( res ).to.eql( {
            domains: [ 'example.com' ],
            clear_auth: false,
            mac_auth: false,
            master_auth: false,
            master_auto_reg: false,
            auth_service: false,
        } ) );
    } ) );

    it ( 'should refuse to ensure user', $as_test(
        ( as ) => {
            const mf = ccm.iface( MANAGE_FACE );
            mf.ensureUser( as, 'user1', 'example.org' );
        },
        ( as, err ) => {
            expect( err ).to.equal( 'InternalError' );
            expect( as.state.error_info ).to.equal( 'AuthService is not enabled' );
            as.success();
        }
    ) );

    it ( 'should config', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );

        mf.setup( as,
            [ 'example.com', 'example.org' ],
            true,
            true,
            true,
            true,
            true );
        mf.genConfig( as );
        as.add( ( as, res ) => expect( res ).to.eql( {
            domains: [ 'example.com', 'example.org' ],
            clear_auth: true,
            mac_auth: true,
            master_auth: true,
            master_auto_reg: true,
            auth_service: true,
        } ) );
    } ) );

    it ( 'should ensure local user', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );
        let local_id;

        mf.ensureUser( as, 'user1', 'example.org' );
        as.add( ( as, res ) => {
            local_id = res;
        } );

        mf.ensureUser( as, 'user1', 'example.org' );
        as.add( ( as, res ) => expect( res ).equal( local_id ) );

        mf.ensureUser( as, 'user1', 'example.com' );
        as.add( ( as, res ) => expect( res ).not.equal( local_id ) );
    } ) );

    it ( 'should ensure local service', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );
        let local_id;

        mf.ensureService( as, 'service1', 'example.org' );
        as.add( ( as, res ) => {
            local_id = res;
        } );

        mf.ensureService( as, 'service1', 'example.org' );
        as.add( ( as, res ) => expect( res ).equal( local_id ) );

        mf.ensureService( as, 'service1', 'example.com' );
        as.add( ( as, res ) => expect( res ).not.equal( local_id ) );
    } ) );

    it ( 'should ensure foreign user with race', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );

        const p = as.parallel();
        let local_id;

        p.add( ( as ) => {
            mf.ensureUser( as, 'user1', 'example.net' );
            as.add( ( as, res ) => {
                local_id = res;
            } );
        } );
        p.add( ( as ) => {
            mf.ensureUser( as, 'user1', 'example.net' );
            as.add( ( as, res ) => expect( res ).equal( local_id ) );
        } );
    } ) );
};
