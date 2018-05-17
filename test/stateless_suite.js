'use strict';

const expect = require( 'chai' ).expect;
const $as_test = require( 'futoin-asyncsteps/testcase' );
const {
    MANAGE_FACE,
    STLS_MANAGE_FACE,
} = require( '../lib/main' );

module.exports = function( { describe, it, vars } ) {
    let ccm;
    let manage;
    let stls_manage;
    let user1_id;
    let service1_id;

    before( 'manage', $as_test( ( as ) => {
        ccm = vars.ccm;
        manage = ccm.iface( MANAGE_FACE );
        stls_manage = ccm.iface( STLS_MANAGE_FACE );

        manage.ensureUser( as, 'stlsuser1', 'example.com' );
        as.add( ( as, res ) => user1_id = res );

        manage.ensureService( as, 'stlssvc1', 'example.com' );
        as.add( ( as, res ) => service1_id = res );
    } ) );

    describe( 'Manage', function() {
        it ( 'should generate Password', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, service1_id, false );

            as.add( ( as, secret ) => {
                expect( secret.length ).to.equal( 16 );

                stls_manage.getSecret( as, user1_id, service1_id, false );
                as.add( ( as, new_secret ) => {
                    expect( new_secret ).to.eql( secret );
                } );

                stls_manage.genNewSecret( as, user1_id, service1_id, false );
                as.add( ( as, new_secret ) => {
                    expect( new_secret ).not.to.eql( secret );
                } );
            } );
        } ) );

        it ( 'should remove Password', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, service1_id, false );
            stls_manage.removeSecret( as, user1_id, service1_id, false );

            as.add(
                ( as ) => {
                    stls_manage.getSecret( as, user1_id, service1_id, false );
                    as.add( ( as ) => as.error( 'Fail' ) );
                },
                ( as, err ) => {
                    if ( err === 'NotSet' ) {
                        as.success();
                    }
                }
            );

            stls_manage.removeSecret( as, user1_id, service1_id, false );
        } ) );

        it ( 'should generate MAC secret', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, service1_id, true );

            as.add( ( as, secret ) => {
                expect( secret.length ).to.equal( 44 );

                stls_manage.getSecret( as, user1_id, service1_id, true );
                as.add( ( as, new_secret ) => {
                    expect( new_secret ).to.eql( secret );
                } );

                stls_manage.genNewSecret( as, user1_id, service1_id, true );
                as.add( ( as, new_secret ) => {
                    expect( new_secret ).not.to.eql( secret );
                } );
            } );
        } ) );

        it ( 'should remove MAC secret', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, service1_id, true );
            stls_manage.removeSecret( as, user1_id, service1_id, true );

            as.add(
                ( as ) => {
                    stls_manage.getSecret( as, user1_id, service1_id, true );
                    as.add( ( as ) => as.error( 'Fail' ) );
                },
                ( as, err ) => {
                    if ( err === 'NotSet' ) {
                        as.success();
                    }
                }
            );

            stls_manage.removeSecret( as, user1_id, service1_id, true );
        } ) );

        it ( 'should obey config', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, service1_id, false );
            stls_manage.genNewSecret( as, user1_id, service1_id, true );

            // Disabled Clear auth
            as.add(
                ( as ) => {
                    vars.app._scope.config.clear_auth = false;
                    stls_manage.genNewSecret( as, user1_id, service1_id, true );
                    stls_manage.genNewSecret( as, user1_id, service1_id, false );
                    as.add( ( as ) => as.error( 'Fail' ) );
                },
                ( as, err ) => {
                    vars.app._scope.config.clear_auth = true;

                    if ( ( err === 'InternalError' ) &&
                         ( as.state.error_info === 'Clear text auth is disabled' )
                    ) {
                        as.success();
                    }
                }
            );

            // Disabled MAC auth
            as.add(
                ( as ) => {
                    vars.app._scope.config.mac_auth = false;
                    stls_manage.genNewSecret( as, user1_id, service1_id, false );
                    stls_manage.genNewSecret( as, user1_id, service1_id, true );
                    as.add( ( as ) => as.error( 'Fail' ) );
                },
                ( as, err ) => {
                    vars.app._scope.config.mac_auth = true;

                    if ( ( err === 'InternalError' ) &&
                         ( as.state.error_info === 'Stateless MAC auth is disabled' )
                    ) {
                        as.success();
                    }
                }
            );
        } ) );
    } );


    describe( 'Auth', function() {
    } );
};
