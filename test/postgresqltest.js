'use strict';

const child_process = require( 'child_process' );
const $as = require( 'futoin-asyncsteps' );
const DBAutoConfig = require( 'futoin-database/AutoConfig' );
const integration_suite = require( './integrationsuite' );

const AdvancedCCM = require( 'futoin-invoker/AdvancedCCM' );

const DB_PORT = process.env.POSTGRESQL_PORT || '5436';

describe( 'PostgreSQL', function() {
    before( function( done ) {
        this.timeout( 30e3 );
        const ccm = new AdvancedCCM();

        $as().add(
            ( as ) => {
                DBAutoConfig( as, ccm, null, {
                    DB_TYPE: 'postgresql',
                    DB_HOST: '127.0.0.1',
                    DB_PORT: DB_PORT,
                    DB_USER: 'ftntest',
                    DB_PASS: 'test',
                    DB_DB: 'postgres',
                } );
                as.add( ( as ) => {
                    ccm.db().query( as, 'DROP DATABASE IF EXISTS ftnsec' );
                    ccm.db().query( as, 'CREATE DATABASE ftnsec' );
                } );
                as.add( ( as ) => {
                    const flyway_locations = [
                        `filesystem:${__dirname}/../sql/postgresql`,
                        `filesystem:${__dirname}/../node_modules/futoin-eventstream/sql/active/postgresql`,
                        `filesystem:${__dirname}/../node_modules/futoin-ftnsec/sql/postgresql`,
                    ].join( ',' );

                    let res;

                    res = child_process.spawnSync(
                        'cid',
                        [
                            'tool', 'exec', 'flyway', '--',
                            'migrate',
                            `-url=jdbc:postgresql://127.0.0.1:${DB_PORT}/ftnsec`,
                            '-user=ftntest',
                            '-password=test',
                            `-locations=${flyway_locations}`,
                        ]
                    );

                    if ( res.status ) {
                        console.log( res.stderr.toString() );
                        as.error( 'Fail' );
                    }

                    ccm.close();
                } );
            },
            ( as, err ) => {
                console.log( err );
                console.log( as.state.error_info );
                done( as.state.last_exception || 'Fail' );
            }
        ).add( ( as ) => done() )
            .execute();
    } );

    const ccm = new AdvancedCCM();
    const vars = {
        as: null,
        ccm,
    };

    before( 'specific', function( done ) {
        $as()
            .add(
                ( as ) => {
                    DBAutoConfig( as, ccm, {
                        ftnsec: {},
                    }, {
                        DB_FTNSEC_TYPE: 'postgresql',
                        DB_FTNSEC_HOST: '127.0.0.1',
                        DB_FTNSEC_PORT: DB_PORT,
                        DB_FTNSEC_USER: 'ftntest',
                        DB_FTNSEC_DB: 'ftnsec',
                        DB_FTNSEC_PASS: 'test',
                    } );
                },
                ( as, err ) => {
                    console.log( err );
                    console.log( as.state.error_info );
                    done( as.state.last_exception || 'Fail' );
                }
            )
            .add( ( as ) => done() )
            .execute();
    } );

    after( 'specific', function() {
        ccm.close();
    } );

    integration_suite( describe, it, vars );
} );
