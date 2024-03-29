'use strict';

const expect = require( 'chai' ).expect;
const crypto = require( 'crypto' );
const $as_test = require( 'futoin-asyncsteps/testcase' );

const MasterAutoregFace = require( '../MasterAutoregFace' );
const { AdvancedCCM } = require( 'futoin-invoker' );

const {
    MANAGE_FACE,
    STLS_AUTH_FACE,
    STLS_MANAGE_FACE,
} = require( '../lib/main' );
const {
    reqinfo2source,
} = require( '../lib/util' );
const tinyJsonHttp = require( 'tiny-json-http' );

module.exports = function( { describe, it, vars } ) {
    let ccm;
    let manage;
    let stls_manage;
    let stls_auth;
    let user1_id;
    let service1_id;
    let system_id;

    before( 'manage', $as_test( ( as ) => {
        ccm = vars.ccm;
        manage = ccm.iface( MANAGE_FACE );
        stls_manage = ccm.iface( STLS_MANAGE_FACE );
        stls_auth = ccm.iface( STLS_AUTH_FACE );
        system_id = vars.app._scope.system_local_id;

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
        it ( 'should check Clear', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, system_id, false );

            as.add( ( as, secret ) => {
                stls_auth.checkClear(
                    as,
                    { user : user1_id, secret },
                    {}
                );
                as.add( ( as, { local_id, global_id } ) => {
                    expect( local_id ).to.equal( user1_id );
                    expect( global_id ).to.equal( 'stlsuser1@example.com' );
                } );
            } );
        } ) );

        it ( 'should check MAC', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, system_id, true );

            as.add( ( as, key ) => {
                const raw_key = Buffer.from( key, 'base64' );
                const base = Buffer.from( '1234567890' );
                const sig = crypto.createHmac( 'sha256', raw_key )
                    .update( base ).digest()
                    .toString( 'base64' );

                stls_auth.checkMAC(
                    as,
                    base,
                    {
                        user : user1_id,
                        algo : 'HS256',
                        sig,
                    },
                    {}
                );
                as.add( ( as, { local_id, global_id } ) => {
                    expect( local_id ).to.equal( user1_id );
                    expect( global_id ).to.equal( 'stlsuser1@example.com' );
                } );
            } );
        } ) );

        it ( 'should gen MAC', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, system_id, true );

            as.add( ( as, key ) => {
                const raw_key = Buffer.from( key, 'base64' );
                const base = Buffer.from( '1234567890' );
                const sig = crypto.createHmac( 'sha384', raw_key )
                    .update( base ).digest()
                    .toString( 'base64' );

                stls_auth.genMAC(
                    as,
                    base,
                    {
                        user : user1_id,
                        algo : 'HS384',
                        sig : 'abcdef',
                    }
                );
                as.add( ( as, res ) => {
                    expect( res ).to.eql( sig );
                } );
            } );
        } ) );

        it ( 'should return MAC secret', $as_test( ( as ) => {
            stls_manage.genNewSecret( as, user1_id, system_id, true );

            as.add( ( as, key ) => {
                stls_auth.getMACSecret(
                    as,
                    user1_id
                );
                as.add( ( as, res ) => {
                    expect( res ).to.eql( key );
                } );
            } );
        } ) );

        it ( 'should detect unknown user in Clear', $as_test(
            ( as ) => {
                stls_auth.checkClear(
                    as,
                    { user : '1234567890123456789012', secret: '123467890' },
                    {}
                );
            },
            ( as, err ) => {
                expect( as.state.error_info )
                    .to.equal( 'Invalid user or password: 1234567890123456789012' );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );

        it ( 'should detect unknown user in MAC', $as_test(
            ( as ) => {
                stls_auth.checkMAC(
                    as,
                    Buffer.from( 'abcdefghijklmnopqrstuvwxyz' ),
                    {
                        user : '1234567890123456789012',
                        algo : 'HS256',
                        sig : 'abcdefghijklmnopqrstuvwxyz',
                    },
                    {}
                );
            },
            ( as, err ) => {
                expect( as.state.error_info )
                    .to.equal( 'Invalid user or password: 1234567890123456789012' );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );

        it ( 'should detect disabled user in Clear', $as_test(
            ( as ) => {
                stls_manage.genNewSecret( as, user1_id, system_id, false );
                as.add( ( as, secret ) => {
                    manage.setUserInfo( as, user1_id, false );
                    stls_auth.checkClear(
                        as,
                        { user : user1_id, secret },
                        {}
                    );
                } );
            },
            ( as, err ) => {
                expect( as.state.error_info )
                    .to.equal( `User is not enabled: ${user1_id}` );
                expect( err ).to.equal( 'SecurityError' );
                manage.setUserInfo( as, user1_id, true );
            }
        ) );

        it ( 'should detect disabled user in Clear', $as_test(
            ( as ) => {
                stls_manage.genNewSecret( as, user1_id, system_id, true );
                as.add( ( as, key ) => {
                    manage.setUserInfo( as, user1_id, false );

                    const raw_key = Buffer.from( key, 'base64' );
                    const base = Buffer.from( '1234567890' );
                    const sig = crypto.createHmac( 'sha256', raw_key )
                        .update( base ).digest()
                        .toString( 'base64' );

                    stls_auth.checkMAC(
                        as,
                        base,
                        {
                            user : user1_id,
                            algo : 'HS256',
                            sig,
                        },
                        {}
                    );
                } );
            },
            ( as, err ) => {
                expect( as.state.error_info )
                    .to.equal( `User is not enabled: ${user1_id}` );
                expect( err ).to.equal( 'SecurityError' );
                manage.setUserInfo( as, user1_id, true );
            }
        ) );

        it ( 'should detect invalid password', $as_test(
            ( as ) => {
                stls_manage.genNewSecret( as, user1_id, system_id, false );
                as.add( ( as, secret ) => {
                    stls_auth.checkClear(
                        as,
                        { user : user1_id, secret : secret.slice( 1 ) },
                        {}
                    );
                } );
            },
            ( as, err ) => {
                expect( as.state.error_info )
                    .to.equal( `Invalid user or password: ${user1_id}` );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );

        it ( 'should detect invalid signature', $as_test(
            ( as ) => {
                stls_manage.genNewSecret( as, user1_id, system_id, true );
                as.add( ( as, key ) => {
                    const raw_key = Buffer.from( key, 'base64' );
                    const base = Buffer.from( '1234567890' );
                    const sig = crypto.createHmac( 'sha256', raw_key )
                        .update( base ).digest()
                        .toString( 'base64' );

                    stls_auth.checkMAC(
                        as,
                        base,
                        {
                            user : user1_id,
                            algo : 'HS256',
                            sig : sig.slice( 1 ),
                        },
                        {}
                    );
                } );
            },
            ( as, err ) => {
                expect( as.state.error_info )
                    .to.equal( `Invalid user or password: ${user1_id}` );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );

        it ( 'should detect if clear auth is disabled', $as_test(
            ( as ) => {
                vars.app._scope.config.clear_auth = false;
                stls_auth.checkClear(
                    as,
                    { user : '1234567890123456789012', secret: '123467890' },
                    {}
                );
            },
            ( as, err ) => {
                vars.app._scope.config.clear_auth = true;
                expect( as.state.error_info )
                    .to.equal( 'Clear text auth is disabled' );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );

        it ( 'should detect if MAC auth is disabled', $as_test(
            ( as ) => {
                vars.app._scope.config.mac_auth = false;
                stls_auth.checkMAC(
                    as,
                    Buffer.from( 'abcdefghijklmnopqrstuvwxyz' ),
                    {
                        user : '1234567890123456789012',
                        algo : 'HS256',
                        sig : 'abcdefghijklmnopqrstuvwxyz',
                    },
                    {}
                );
            },
            ( as, err ) => {
                vars.app._scope.config.mac_auth = true;
                expect( as.state.error_info )
                    .to.equal( 'Stateless MAC auth is disabled' );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );
    } );

    describe( 'SimpleSecurityProvider', function() {
        it ( 'should work with Clear', $as_test( ( as ) => {
            const tmpccm = new AdvancedCCM();

            stls_manage.genNewSecret( as, user1_id, system_id, false );
            as.add( ( as, secret ) => {
                MasterAutoregFace.register(
                    as, tmpccm, 'test',
                    `secure+http://localhost:${vars.httpPort}`,
                    `${user1_id}:${secret}`
                );
            } );
            as.add( ( as ) => {
                tmpccm.iface( 'test' ).ping( as, 1234 );
            } );
            as.add( ( as, res ) => {
                expect( res ).to.equal( 1234 );
                tmpccm.close();
            } );
        } ) );

        it ( 'should detect SecurityError with Clear', $as_test(
            ( as ) => {
                const tmpccm = new AdvancedCCM();
                as.state.tmpccm = tmpccm;

                stls_manage.genNewSecret( as, user1_id, system_id, false );
                as.add( ( as, secret ) => {
                    MasterAutoregFace.register(
                        as, tmpccm, 'test',
                        `secure+http://localhost:${vars.httpPort}`,
                        `${user1_id}:${secret}123`
                    );
                } );
                as.add( ( as ) => {
                    tmpccm.iface( 'test' ).ping( as, 1234 );
                } );
            },
            ( as, err ) => {
                expect( err ).to.equal( 'SecurityError' );
                expect( as.state.error_info ).to
                    .match( /^Invalid user or password:/ );
                as.state.tmpccm.close();
                as.success();
            }
        ) );

        it ( 'should work with MAC', $as_test( ( as ) => {
            const tmpccm = new AdvancedCCM();

            stls_manage.genNewSecret( as, user1_id, system_id, true );
            as.add( ( as, macKey ) => {
                MasterAutoregFace.register(
                    as, tmpccm, 'test',
                    `secure+http://localhost:${vars.httpPort}`,
                    `-smac:${user1_id}`,
                    { macKey }
                );
            } );
            as.add( ( as ) => {
                tmpccm.iface( 'test' ).ping( as, 1234 );
            } );
            as.add( ( as, res ) => {
                expect( res ).to.equal( 1234 );
                tmpccm.close();
            } );
        } ) );

        it ( 'should detect SecurityError with MAC', $as_test(
            ( as ) => {
                const tmpccm = new AdvancedCCM();
                as.state.tmpccm = tmpccm;

                stls_manage.genNewSecret( as, user1_id, system_id, true );
                as.add( ( as, macKey ) => {
                    MasterAutoregFace.register(
                        as, tmpccm, 'test',
                        `secure+http://localhost:${vars.httpPort}`,
                        `-smac:${user1_id}`,
                        { macKey: '123' + macKey }
                    );
                } );
                as.add( ( as ) => {
                    tmpccm.iface( 'test' ).ping( as, 1234 );
                } );
            },
            ( as, err ) => {
                expect( err ).to.equal( 'SecurityError' );
                expect( as.state.error_info ).to
                    .match( /^Invalid user or password:/ );
                as.state.tmpccm.close();
                as.success();
            }
        ) );

        it ( 'should collect user-agent and client token', $as_test( ( as ) => {
            const spec = {
                iface: 'futoin.test.source',
                version: '0.1',
                ftn3rev: '1.9',
                funcs: {
                    dump: {
                        result: 'map',
                    },
                },
                requires: [ 'AllowAnonymous' ],
            };

            vars.app._public_executor.register( as, 'futoin.test.source:0.1', {
                dump : ( as, reqinfo ) => {
                    reqinfo.result( reqinfo2source( reqinfo ) );
                },
            }, [ spec ] );

            as.await( tinyJsonHttp.post( {
                url: `http://localhost:${vars.httpPort}`,
                data: {
                    f: 'futoin.test.source:0.1:dump',
                },
                headers: {
                    'user-agent': 'My Test',
                    cookie: 'FTNID=12345',
                },
            } ) );
            as.add( ( as, res ) => {
                expect( res.body ).to.eql( { r:
                    {
                        source_ip: '::1',
                        user_agent: 'My Test',
                        client_token: '12345',
                    },
                } );
            } );
        } ) );
    } );
};
