'use strict';

const expect = require( 'chai' ).expect;

const $as = require( 'futoin-asyncsteps' );

module.exports = function( describe, it, vars ) {
    require( '../lib/main' );
    vars.STORAGE_PASSWORD = 'e3b694af320229f9b464a358eae063a8';

    beforeEach( 'common', function() {
        vars.as = $as();
    } );
};
