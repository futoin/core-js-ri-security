'use strict';

const child_process = require( 'child_process' );
const $as_test = require( 'futoin-asyncsteps/testcase' );
const $as = require( 'futoin-asyncsteps' );
const DBAutoConfig = require( 'futoin-database/AutoConfig' );
const integration_suite = require( './integrationsuite' );
const fs = require( 'fs' );

const AdvancedCCM = require( 'futoin-invoker/AdvancedCCM' );

describe( 'SQLite', function() {
    const ftnsec_db = `${__dirname}/ftnsec.db`;

    before( $as_test( function( as ) {
        this.timeout( 30e3 );
        const ccm = new AdvancedCCM();

        as.add( ( as ) => {
            const Executor = require( 'futoin-executor/Executor' );
            const SQLiteService = require( 'futoin-database/SQLiteService' );

            for ( let f of [ ftnsec_db ] ) {
                if ( fs.existsSync( f ) ) {
                    fs.unlinkSync( f );
                }

                const executor = new Executor( ccm );
                SQLiteService.register( as, executor, {
                    port: f,
                } );

                as.add( ( as ) => executor.close() );
            }
        } );
        as.add( ( as ) => {
            ccm.close();

            const flyway_locations = [
                `filesystem:${__dirname}/../sql/sqlite`,
                `filesystem:${__dirname}/../node_modules/futoin-eventstream/sql/active/sqlite`,
                `filesystem:${__dirname}/../node_modules/futoin-secvault/sql/sqlite`,
            ].join( ',' );

            let res;

            res = child_process.spawnSync(
                'cid',
                [
                    'tool', 'exec', 'flyway', '--',
                    'migrate',
                    `-url=jdbc:sqlite:${ftnsec_db}`,
                    '-user=fake',
                    '-password=fake',
                    `-locations=${flyway_locations}`,
                ]
            );

            if ( res.status ) {
                console.log( res.stderr.toString() );
                as.error( 'Fail' );
            }
        } );
    } ) );

    integration_suite( describe, it, {
        DB_FTNSEC_TYPE: 'sqlite',
        DB_FTNSEC_SOCKET: ftnsec_db,
    } );
} );
