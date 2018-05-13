'use strict';

const expect = require( 'chai' ).expect;
const $as_test = require( 'futoin-asyncsteps/testcase' );
const {
    MANAGE_FACE,
} = require( '../lib/main' );

module.exports = function( describe, it, vars ) {
    const ccm = vars.ccm;

    it ( 'get config', $as_test( ( as ) => {
        ccm.iface( MANAGE_FACE ).genConfig( as );
        as.add( ( as, res ) => expect( res ).to.eql( {
            domain: 'example.com',
            clear_auth: false,
            mac_auth: false,
            master_auth: false,
            master_auto_reg: false,
            auth_service: false,
        } ) );
    } ) );

    it ( 'should config', $as_test( ( as ) => {
        const mf = ccm.iface( MANAGE_FACE );

        mf.setup( as,
            'example.org',
            true,
            true,
            true,
            true,
            true );
        mf.genConfig( as );
        as.add( ( as, res ) => expect( res ).to.eql( {
            domain: 'example.org',
            clear_auth: true,
            mac_auth: true,
            master_auth: true,
            master_auto_reg: true,
            auth_service: true,
        } ) );
    } ) );
};
