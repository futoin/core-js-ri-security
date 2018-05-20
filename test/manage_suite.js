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
            password_len: 16,
            key_bits: 256,
            def_service_ms_max: 10,
            def_user_ms_max: 0,
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
            password_len: 16,
            key_bits: 256,
            def_service_ms_max: 10,
            def_user_ms_max: 0,
        } ) );
    } ) );

    it ( 'should ensure local user', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );

        mf.ensureUser( as, 'user1', 'example.org' );
        as.add( ( as, local_id ) => {
            mf.ensureUser( as, 'user1', 'example.org' );
            as.add( ( as, res ) => expect( res ).equal( local_id ) );

            mf.ensureUser( as, 'user1', 'example.com' );
            as.add( ( as, res ) => expect( res ).not.equal( local_id ) );
        } );
    } ) );

    it ( 'should ensure local service', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );

        mf.ensureService( as, 'service1', 'example.org' );
        as.add( ( as, local_id ) => {
            mf.ensureService( as, 'service1', 'example.org' );
            as.add( ( as, res ) => expect( res ).equal( local_id ) );

            mf.ensureService( as, 'service1', 'example.com' );
            as.add( ( as, res ) => expect( res ).not.equal( local_id ) );
        } );
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

    it ( 'should update user info', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );

        mf.ensureUser( as, 'user2', 'example.org' );
        as.add( ( as, local_id ) => {
            mf.getUserInfo( as, local_id );
            as.add( ( as, res ) => expect( res ).eql( {
                local_id,
                global_id: 'user2@example.org',
                is_local: true,
                is_service: false,
                is_enabled: true,
                ms_max: 0,
                ds_max: 0,
                created : res.created,
                updated : res.updated,
            } ) );

            mf.setUserInfo( as, local_id, false );
            as.add( ( as, res ) => expect( res ).to.be.true );

            mf.getUserInfo( as, local_id );
            as.add( ( as, res ) => expect( res ).eql( {
                local_id,
                global_id: 'user2@example.org',
                is_local: true,
                is_service: false,
                is_enabled: false,
                ms_max: 0,
                ds_max: 0,
                created : res.created,
                updated : res.updated,
            } ) );

            // ms_max / ds_max set
            mf.call( as, 'setUserInfo', { local_id, ms_max : 30, ds_max: 40 } );
            as.add( ( as, res ) => expect( res ).to.be.true );

            mf.getUserInfo( as, local_id );
            as.add( ( as, res ) => expect( res ).eql( {
                local_id,
                global_id: 'user2@example.org',
                is_local: true,
                is_service: false,
                is_enabled: false,
                ms_max: 30,
                ds_max: 40,
                created : res.created,
                updated : res.updated,
            } ) );

            // ms_max / ds_max default
            mf.call( as, 'setUserInfo', { local_id, ms_max : 0, ds_max: 0 } );
            as.add( ( as, res ) => expect( res ).to.be.true );

            mf.getUserInfo( as, local_id );
            as.add( ( as, res ) => expect( res ).eql( {
                local_id,
                global_id: 'user2@example.org',
                is_local: true,
                is_service: false,
                is_enabled: false,
                ms_max: 0,
                ds_max: 0,
                created : res.created,
                updated : res.updated,
            } ) );
        } );
    } ) );

    it ( 'should fail on unknown user', $as_test(
        ( as ) => ccm.iface( MANAGE_FACE ).getUserInfo( as, '1234567890123456789012' ),
        ( as, err ) => {
            expect( err ).to.equal( 'UnknownUser' );
            expect( as.state.error_info ).to.equal( 'UserID: 1234567890123456789012' );
            as.success();
        }
    ) );
};
