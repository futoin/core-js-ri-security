'use strict';

let expect;
before( async () => {
    ( { expect } = ( await import( 'chai' ) ) );
} );
