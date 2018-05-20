'use strict';

const expect = require( 'chai' ).expect;
const crypto = require( 'crypto' );
const $as_test = require( 'futoin-asyncsteps/testcase' );
const {
    SVKEY_FACE,
    MANAGE_FACE,
    MASTER_AUTH_FACE,
    MASTER_AUTOREG_FACE,
    MASTER_MANAGE_FACE,
} = require( '../lib/main' );
const hkdf = require( 'futoin-hkdf' );
const moment = require( 'moment' );

module.exports = function( { describe, it, vars } ) {
    let ccm;
    let manage;
    let mstr_manage;
    let mstr_auth;
    let mstr_autoreg;
    let user1_id;
    let service1_id;
    let system_id;

    before( 'manage', $as_test( ( as ) => {
        ccm = vars.ccm;
        manage = ccm.iface( MANAGE_FACE );
        mstr_manage = ccm.iface( MASTER_MANAGE_FACE );
        mstr_auth = ccm.iface( MASTER_AUTH_FACE );
        mstr_autoreg = ccm.iface( MASTER_AUTOREG_FACE );
        system_id = vars.app._scope.system_local_id;

        manage.ensureUser( as, 'mstruser1', 'example.com' );
        as.add( ( as, res ) => user1_id = res );

        manage.ensureService( as, 'mstrsvc1', 'example.com' );
        as.add( ( as, res ) => service1_id = res );
    } ) );

    describe( 'Manage', function() {
        it ( 'should generate new key', $as_test( ( as ) => {
            mstr_manage.getNewPlainSecret( as, service1_id );
            as.add( ( as, { id, secret } ) => {
                expect( Buffer.from( secret, 'base64' ).length ).to.equal( 32 );
            } );
        } ) );

        it ( 'should clear old keys', $as_test( ( as ) => {
            const svkey = ccm.iface( SVKEY_FACE );
            as.repeat( 3, ( as, i ) => {
                svkey.generateKey(
                    as,
                    `${service1_id}:MSTR::${i}`,
                    [ 'shared', 'derive' ],
                    'HMAC',
                    {
                        bits : 256,
                        local_id : service1_id,
                        global_id : 'mstrsvc1.example.com',
                    }
                );
                svkey.generateKey(
                    as,
                    `${service1_id}:MSTR:other:${i}:${user1_id}`,
                    [ 'shared', 'derive' ],
                    'HMAC',
                    { bits : 256 }
                );
                as.add( ( as, key_id ) => {
                    svkey.deriveKey(
                        as,
                        `${key_id}:DRV:HKDF256:HMAC:example.com:MAC:20180101`,
                        [ 'encrypt', 'sign' ],
                        'HMAC',
                        256,
                        key_id,
                        'HKDF',
                        'SHA-256',
                        Buffer.from( 'MAC' ),
                        {}
                    );
                } );
            } );

            // Check
            svkey.listKeys( as, `${service1_id}:MSTR:` );
            as.add( ( as, res ) => {
                expect( res.length ).to.equal( 6 );
            } );

            // Gen enw
            mstr_manage.getNewPlainSecret( as, service1_id );
            as.add( ( as, { id, secret } ) => {
                expect( Buffer.from( secret, 'base64' ).length ).to.equal( 32 );
            } );

            // Check
            svkey.listKeys( as, `${service1_id}:MSTR:` );
            as.add( ( as, res ) => {
                expect( res.length ).to.equal( 1 );
            } );
        } ) );

        it ( 'should detect if master auth is disabled', $as_test(
            ( as ) => {
                vars.app._scope.config.master_auth = false;
                mstr_manage.getNewPlainSecret( as, service1_id );
            },
            ( as, err ) => {
                vars.app._scope.config.master_auth = true;
                expect( as.state.error_info )
                    .to.equal( 'Master auth is disabled' );
                expect( err ).to.equal( 'SecurityError' );
                as.success();
            }
        ) );
    } );

    describe( 'Auth', function() {
        let msid;
        let raw_key;
        let prm;
        let derived_key256;
        let derived_key512;

        before( $as_test( ( as ) => {
            mstr_manage.getNewPlainSecret( as, service1_id );
            as.add( ( as, { id, secret } ) => {
                msid = id;
                raw_key = Buffer.from( secret, 'base64' );
                prm = moment.utc().format( 'YYYYMMDD' );
                derived_key256 = hkdf( raw_key, 32, {
                    salt: Buffer.from( `example.com:MAC` ),
                    info: prm,
                    hash: 'sha256',
                } );
                derived_key512 = hkdf( raw_key, 32, {
                    salt: Buffer.from( `example.com:MAC` ),
                    info: prm,
                    hash: 'sha512',
                } );

                // just in case
                expect( derived_key256.toString( 'base64' ) )
                    .not.to.equal( derived_key512.toString( 'base64' ) );
            } );
        } ) );

        describe( 'checkMAC', function() {
            it ( 'should work correctly', $as_test( ( as ) => {
                const tests = {
                    md5 : 'HMD5',
                    sha256 : 'HS256',
                    sha384 : 'HS384',
                    sha512 : 'HS512',
                };

                as.forEach( tests, ( as, hf, algo ) => {
                    const base = crypto.randomBytes( 250 );
                    const sig256 = crypto.createHmac( hf, derived_key256 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    const sig512 = crypto.createHmac( hf, derived_key512 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo,
                            kds: 'HKDF256',
                            prm,
                            sig: sig256,
                        },
                        {}
                    );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo,
                            kds: 'HKDF512',
                            prm,
                            sig: sig512,
                        },
                        {}
                    );
                } );
            } ) );

            it ( 'should detect invalid signature', $as_test(
                ( as ) => {
                    const base = crypto.randomBytes( 250 );
                    const sig = crypto.createHmac( 'sha256', derived_key256 )
                        .update( base.slice( 1 ) ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo: 'HS256',
                            kds: 'HKDF256',
                            prm,
                            sig,
                        },
                        {}
                    );
                },
                ( as, err ) => {
                    expect( err ).equal( 'SecurityError' );
                    expect( as.state.error_info ).equal( 'Authentication failed' );
                    as.success();
                }
            ) );

            it ( 'should detect invalid derived key', $as_test(
                ( as ) => {
                    const base = crypto.randomBytes( 250 );
                    const sig = crypto.createHmac( 'sha256', crypto.randomBytes( 32 ) )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo: 'HS256',
                            kds: 'HKDF256',
                            prm,
                            sig,
                        },
                        {}
                    );
                },
                ( as, err ) => {
                    expect( err ).equal( 'SecurityError' );
                    expect( as.state.error_info ).equal( 'Authentication failed' );
                    as.success();
                }
            ) );

            it ( 'should detect KDS mismatch', $as_test(
                ( as ) => {
                    const base = crypto.randomBytes( 250 );
                    const sig = crypto.createHmac( 'sha256', derived_key256 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo: 'HS256',
                            kds: 'HKDF512',
                            prm,
                            sig,
                        },
                        {}
                    );
                },
                ( as, err ) => {
                    expect( err ).equal( 'SecurityError' );
                    expect( as.state.error_info ).equal( 'Authentication failed' );
                    as.success();
                }
            ) );

            it ( 'should detect algo mismatch', $as_test(
                ( as ) => {
                    const base = crypto.randomBytes( 250 );
                    const sig = crypto.createHmac( 'sha512', derived_key256 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo: 'HS256',
                            kds: 'HKDF256',
                            prm,
                            sig,
                        },
                        {}
                    );
                },
                ( as, err ) => {
                    expect( err ).equal( 'SecurityError' );
                    expect( as.state.error_info ).equal( 'Authentication failed' );
                    as.success();
                }
            ) );

            it ( 'should detect prm mismatch', $as_test(
                ( as ) => {
                    const base = crypto.randomBytes( 250 );
                    const sig = crypto.createHmac( 'sha256', derived_key256 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo: 'HS256',
                            kds: 'HKDF256',
                            prm: '20180101',
                            sig,
                        },
                        {}
                    );
                },
                ( as, err ) => {
                    expect( err ).equal( 'SecurityError' );
                    expect( as.state.error_info ).equal( 'Authentication failed' );
                    as.success();
                }
            ) );

            it ( 'should detect if master auth is disabled', $as_test(
                ( as ) => {
                    vars.app._scope.config.master_auth = false;
                    const base = crypto.randomBytes( 250 );
                    const sig = crypto.createHmac( 'sha256', derived_key256 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.checkMAC(
                        as,
                        base,
                        {
                            msid,
                            algo: 'HS256',
                            kds: 'HKDF256',
                            prm,
                            sig,
                        },
                        {}
                    );
                },
                ( as, err ) => {
                    vars.app._scope.config.master_auth = true;
                    expect( as.state.error_info )
                        .to.equal( 'Master auth is disabled' );
                    expect( err ).to.equal( 'SecurityError' );
                    as.success();
                }
            ) );
        } );

        describe( 'genMAC', function() {
            it ( 'should work correctly', $as_test( ( as ) => {
                const tests = {
                    md5 : 'HMD5',
                    sha256 : 'HS256',
                    sha384 : 'HS384',
                    sha512 : 'HS512',
                };

                as.forEach( tests, ( as, hf, algo ) => {
                    const base = crypto.randomBytes( 250 );

                    // ---
                    const sig256 = crypto.createHmac( hf, derived_key256 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.genMAC(
                        as,
                        base,
                        {
                            msid,
                            algo,
                            kds: 'HKDF256',
                            prm,
                            sig: 'X',
                        }

                    );
                    as.add( ( as, res ) => {
                        expect( res ).to.eql( {
                            msid,
                            algo,
                            kds: 'HKDF256',
                            prm,
                            sig: sig256,
                        } );
                    } );

                    // ---
                    const sig512 = crypto.createHmac( hf, derived_key512 )
                        .update( base ).digest()
                        .toString( 'base64' );
                    mstr_auth.genMAC(
                        as,
                        base,
                        {
                            msid,
                            algo,
                            kds: 'HKDF512',
                            prm,
                            sig: 'X',
                        }
                    );
                    as.add( ( as, res ) => {
                        expect( res ).to.eql( {
                            msid,
                            algo,
                            kds: 'HKDF512',
                            prm,
                            sig: sig512,
                        } );
                    } );
                } );
            } ) );
        } );

        describe( 'exposeDerivedKey', function() {
        } );

        describe( 'getNewEncryptedSecret', function() {
        } );
    } );

    describe( 'Autoreg', function() {
    } );
};
